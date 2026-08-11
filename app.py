"""
avatar-store: hosts hand-made FRC team avatars (full uploaded resolution) plus a
shared default avatar, event-scoped overrides, and a portal to manage them.

Avatars resolve in three tiers for a team at a given event:
  1. event upload   uploads/events/{event}/{team}.png   (crisp, event-branded)
  2. team default   uploads/{team}.png                   (crisp, the team's normal one)
  3. TBA low-res    the ~40px avatar from The Blue Alliance (pixelated fallback)
The audience display fetches GET /avatar/{team}.png?event=<code>&s=160&v=<ver> and
uses tiers 1-2 in place of the blurry FMS avatar; a returned image <= 48px (tier 3
or the display's own FMS base64) is rendered pixelated.

The public can propose avatars at /submit (Google/Firebase sign-in required, team
validated against TBA). Submissions land in a pending queue and Filip is pinged on
Discord to approve/reject them at /admin/queue.

Endpoints (reads are public; .png suffix so Cloudflare edge-caches them):
  GET  /health
  GET  /avatars[?event=CODE]                 -> {teams:{num:ver}, default, events:[...]}
  GET  /avatar/{team}[.png][?event=&s=&v=]   -> image/png | 404
  GET  /avatar/default[.png][?s=]            -> the default avatar | 404
  GET  /submit                               -> public submission page (Google sign-in)
  POST /submit  (Bearer <firebase id token>) -> queue a proposed avatar
  GET  /                                      -> public landing page
  GET  /admin                                 -> upload/manage portal      (auth)
  GET  /admin/queue                           -> pending submissions        (auth)
  POST /upload | /upload-default | /upload-zip | /delete | /delete-default  (auth)
  POST /admin/event/add | /admin/event/delete                              (auth)
  POST /admin/queue/approve | /admin/queue/reject                          (auth)

`v` is the file mtime; the client uses it so a re-upload becomes a fresh URL
(instant update) while responses stay long-cached (immutable). Admin auth is
Authelia forward-auth (Remote-User) with an HTTP Basic fallback.
"""

import base64
import io
import json
import os
import re
import secrets
import time
import zipfile

from datetime import datetime, timezone
from typing import Optional

import httpx
import jwt
from cryptography.x509 import load_pem_x509_certificate

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from PIL import Image, ImageOps

# #region config
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "/uploads")
CACHE_DIR = os.environ.get("CACHE_DIR", "/cache")  # scaled outputs; ephemeral
PENDING_DIR = os.environ.get("PENDING_DIR", "/pending")  # awaiting approval
EVENTS_DIR = os.path.join(UPLOAD_DIR, "events")
EVENTS_JSON = os.path.join(UPLOAD_DIR, "events.json")

PASSWORD = os.environ.get("AVATAR_PORTAL_PASSWORD", "")
TBA_API_KEY = os.environ.get("TBA_API_KEY", "")
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "")
FIREBASE_PROJECT_ID = os.environ.get("FIREBASE_PROJECT_ID", "")
FIREBASE_API_KEY = os.environ.get("FIREBASE_API_KEY", "")
FIREBASE_AUTH_DOMAIN = (
    os.environ.get("FIREBASE_AUTH_DOMAIN") or f"{FIREBASE_PROJECT_ID}.firebaseapp.com"
)
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "https://avatars.filipkin.com").rstrip("/")

IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"}
MIN_SIZE, MAX_SIZE = 16, 1024
DEFAULT_KEY = "default"
# Every upload is transcoded to this one format (RGBA, lossless, transparency) so
# the store holds a single consistent format regardless of what was uploaded.
PREFERRED_FORMAT = "PNG"
EVENT_RE = re.compile(r"^[a-z0-9]+$")  # TBA event key form, e.g. 2026mirr
TBA_BASE = "https://www.thebluealliance.com/api/v3"
# Long-lived + immutable is safe because the client's URLs carry ?v=<mtime>, so a
# changed avatar is a different URL (see module docstring).
CACHE_HEADERS = {"Cache-Control": "public, max-age=86400, immutable"}
# TBA fallback URLs have no ?v=, so cache them fresh-ish (not immutable).
TBA_CACHE_HEADERS = {"Cache-Control": "public, max-age=86400"}
# #endregion

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(CACHE_DIR, exist_ok=True)
os.makedirs(EVENTS_DIR, exist_ok=True)
os.makedirs(PENDING_DIR, exist_ok=True)

app = FastAPI(title="avatar-store")
# The display calls the read endpoints cross-origin from the browser.
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)

# auto_error=False so we can accept EITHER Authelia forward-auth (nginx sets Remote-User
# after SSO) OR the legacy HTTP Basic password (for direct/un-proxied container access).
security = HTTPBasic(auto_error=False)


def require_auth(
    request: Request,
    credentials: Optional[HTTPBasicCredentials] = Depends(security),
) -> bool:
    # Behind avatars.filipkin.com, Authelia forward-auth gates these routes and nginx passes
    # the authenticated user in Remote-User -> no second password prompt (unified SSO).
    if request.headers.get("Remote-User"):
        return True
    # Fallback: HTTP Basic (e.g. hitting the container directly, bypassing nginx).
    if PASSWORD and credentials and secrets.compare_digest(credentials.password, PASSWORD):
        return True
    raise HTTPException(
        status_code=401,
        detail="unauthorized",
        headers={"WWW-Authenticate": "Basic"},
    )


# #region The Blue Alliance
def _tba_get(path: str):
    """GET a TBA v3 path; returns parsed JSON on 200, else None (never raises)."""
    if not TBA_API_KEY:
        return None
    try:
        r = httpx.get(
            TBA_BASE + path, headers={"X-TBA-Auth-Key": TBA_API_KEY}, timeout=10
        )
    except Exception as e:  # network error -> treat as unavailable
        print(f"TBA request failed ({path}): {e}")
        return None
    return r.json() if r.status_code == 200 else None


def tba_team_exists(num: int) -> bool:
    return _tba_get(f"/team/frc{num}/simple") is not None


def _tba_avatar_bytes(num: int, year: int) -> Optional[bytes]:
    media = _tba_get(f"/team/frc{num}/media/{year}")
    if not isinstance(media, list):
        return None
    for m in media:
        if m.get("type") == "avatar":
            b64 = (m.get("details") or {}).get("base64Image")
            if b64:
                try:
                    return base64.b64decode(b64)
                except Exception:
                    return None
    return None


def _current_year() -> int:
    return int(os.environ.get("TBA_YEAR") or datetime.now().year)


def _tba_avatar_cached(num: int) -> Optional[str]:
    """Path to the team's ~40px TBA avatar (fetched once, positively/negatively
    cached in the ephemeral CACHE_DIR), or None if TBA has none."""
    year = _current_year()
    cache = os.path.join(CACHE_DIR, f"tba-{num}-{year}.png")
    neg = os.path.join(CACHE_DIR, f"tba-{num}-{year}.none")
    if os.path.exists(cache):
        return cache
    if os.path.exists(neg) and (time.time() - os.path.getmtime(neg) < 86400):
        return None
    data = _tba_avatar_bytes(num, year)
    if data:
        try:
            with open(cache, "wb") as f:
                f.write(data)
            return cache
        except Exception:
            return None
    open(neg, "w").close()  # negative cache to avoid re-hitting TBA every request
    return None
# #endregion


# #region Firebase sign-in (reuses the fta-buddy project; verify the ID token)
_GOOGLE_CERTS_URL = (
    "https://www.googleapis.com/robot/v1/metadata/x509/"
    "securetoken@system.gserviceaccount.com"
)
_certs_cache: dict = {"data": {}, "exp": 0.0}


def _google_certs() -> dict:
    now = time.time()
    if _certs_cache["data"] and now < _certs_cache["exp"]:
        return _certs_cache["data"]
    r = httpx.get(_GOOGLE_CERTS_URL, timeout=10)
    r.raise_for_status()
    data = r.json()  # {kid: pem cert}
    ttl = 3600
    m = re.search(r"max-age=(\d+)", r.headers.get("Cache-Control", ""))
    if m:
        ttl = int(m.group(1))
    _certs_cache.update(data=data, exp=now + ttl)
    return data


def verify_firebase_token(id_token: str) -> dict:
    """Verify a Firebase ID token (RS256, signed by Google) and return
    {uid, name, email}. Raises 401 on any problem."""
    if not FIREBASE_PROJECT_ID:
        raise HTTPException(status_code=503, detail="sign-in not configured")
    try:
        kid = jwt.get_unverified_header(id_token).get("kid")
        pem = _google_certs().get(kid)
        if not pem:
            raise ValueError("unknown key id")
        public_key = load_pem_x509_certificate(pem.encode()).public_key()
        claims = jwt.decode(
            id_token,
            public_key,
            algorithms=["RS256"],
            audience=FIREBASE_PROJECT_ID,
            issuer=f"https://securetoken.google.com/{FIREBASE_PROJECT_ID}",
        )
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"invalid sign-in: {e}")
    if not claims.get("sub"):
        raise HTTPException(status_code=401, detail="invalid sign-in")
    return {
        "uid": claims.get("sub", ""),
        "name": claims.get("name") or "",
        "email": claims.get("email") or "",
    }
# #endregion


# #region Discord notify
def notify_discord(content: str) -> None:
    """Best-effort webhook ping. Never raises (a submission must not fail because
    Discord is down), but surfaces the error in logs."""
    if not DISCORD_WEBHOOK_URL:
        print("DISCORD_WEBHOOK_URL unset; skipping notify")
        return
    try:
        httpx.post(DISCORD_WEBHOOK_URL, json={"content": content}, timeout=10)
    except Exception as e:
        print(f"discord notify failed: {e}")
# #endregion


# #region events registry
def _events() -> dict:
    if os.path.exists(EVENTS_JSON):
        try:
            with open(EVENTS_JSON) as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def _save_events(d: dict) -> None:
    tmp = EVENTS_JSON + ".tmp"
    with open(tmp, "w") as f:
        json.dump(d, f, indent=2, sort_keys=True)
    os.replace(tmp, EVENTS_JSON)


def _clean_event(code: Optional[str]) -> Optional[str]:
    """Normalize + validate an event code; returns None if empty or malformed
    (also the path-traversal guard: only [a-z0-9] ever touches the filesystem)."""
    code = (code or "").strip().lower()
    return code if code and EVENT_RE.match(code) else None
# #endregion


# #region storage helpers
def _path(key: str, event: Optional[str] = None) -> str:
    """Upload path for a team number (as str) or DEFAULT_KEY, optionally scoped to
    an event. Event codes must already be cleaned via _clean_event."""
    if event:
        return os.path.join(EVENTS_DIR, event, f"{key}.png")
    return os.path.join(UPLOAD_DIR, f"{key}.png")


def _numeric_pngs(directory: str) -> set:
    if not os.path.isdir(directory):
        return set()
    return {
        int(f[:-4])
        for f in os.listdir(directory)
        if f.endswith(".png") and f[:-4].isdigit()
    }


def _team_defaults() -> set:
    return _numeric_pngs(UPLOAD_DIR)


def _event_teams(event: str) -> set:
    return _numeric_pngs(os.path.join(EVENTS_DIR, event))


def _teams() -> list:
    """Teams with a team-default upload (used by /health + the admin/public grids)."""
    return sorted(_team_defaults())


def _version(key: str, event: Optional[str] = None) -> int:
    p = _path(key, event)
    return int(os.path.getmtime(p)) if os.path.exists(p) else 0


def _effective_version(team: int, event: Optional[str]) -> int:
    """The version of the crisp upload the display will actually get for this team
    at this event: the event upload if present, else the team default."""
    if event:
        v = _version(str(team), event)
        if v:
            return v
    return _version(str(team))


def _save_png(img: Image.Image, path: str) -> None:
    """Write `img` in the store's preferred format (RGBA PNG, optimized). Every
    upload is transcoded through here, so whatever was uploaded (jpg/webp/gif/...)
    ends up as one consistent format on disk."""
    if img.mode != "RGBA":
        img = img.convert("RGBA")
    img.save(path, format=PREFERRED_FORMAT, optimize=True)


def _store(key: str, data: bytes, event: Optional[str] = None) -> None:
    """Transcode uploaded bytes to a full-resolution preferred-format image under `key`."""
    p = _path(key, event)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    _save_png(Image.open(io.BytesIO(data)), p)


def _scaled(key: str, s: int, event: Optional[str] = None) -> str:
    """Path to `key` scaled (fit + transparent pad) to s x s, cached and
    regenerated whenever the original changes. Cache filenames are flat, so the
    event goes in the name (never a slash)."""
    src = _path(key, event)
    cache = os.path.join(CACHE_DIR, f"{event or '_'}__{key}-{s}.png")
    if os.path.exists(cache) and os.path.getmtime(cache) >= os.path.getmtime(src):
        return cache
    img = Image.open(src).convert("RGBA")
    out = ImageOps.pad(
        img, (s, s), method=Image.LANCZOS, color=(0, 0, 0, 0), centering=(0.5, 0.5)
    )
    _save_png(out, cache)
    return cache


def _serve_upload(key: str, s: Optional[int], event: Optional[str]) -> FileResponse:
    src = _path(key, event)
    if s is None:
        return FileResponse(src, media_type="image/png", headers=CACHE_HEADERS)
    if s < MIN_SIZE or s > MAX_SIZE:
        raise HTTPException(status_code=400, detail=f"s must be {MIN_SIZE}-{MAX_SIZE}")
    return FileResponse(_scaled(key, s, event), media_type="image/png", headers=CACHE_HEADERS)
# #endregion


# #region public read endpoints
@app.get("/health")
def health():
    return {
        "ok": True,
        "count": len(_teams()),
        "default": _version(DEFAULT_KEY) or None,
        "events": len(_events()),
        "pending": len(_pending_ids()),
    }


@app.get("/avatars")
def avatars(event: Optional[str] = None):
    ev = _clean_event(event) if event else None
    teams = _team_defaults() | (_event_teams(ev) if ev else set())
    body = {
        "teams": {str(t): _effective_version(t, ev) for t in sorted(teams)},
        "default": _version(DEFAULT_KEY) or None,
        "events": sorted(_events().keys()),
    }
    # The client polls this for freshness, so it must never be edge-cached.
    return JSONResponse(body, headers={"Cache-Control": "no-store"})


@app.get("/avatar/{team}")
def avatar(team: str, s: Optional[int] = None, event: Optional[str] = None):
    key = team[:-4] if team.endswith(".png") else team  # allow the .png suffix
    ev = _clean_event(event) if event else None
    if key == DEFAULT_KEY:
        if not os.path.exists(_path(DEFAULT_KEY)):
            raise HTTPException(status_code=404, detail="not found")
        return _serve_upload(DEFAULT_KEY, s, None)
    if not key.isdigit():
        raise HTTPException(status_code=404, detail="not found")
    # Tier 1: event upload.
    if ev and os.path.exists(_path(key, ev)):
        return _serve_upload(key, s, ev)
    # Tier 2: team default upload.
    if os.path.exists(_path(key)):
        return _serve_upload(key, s, None)
    # Tier 3: TBA low-res. Serve it raw (~40px, no upscale) so the client detects
    # it as low-res and renders pixelated.
    tba = _tba_avatar_cached(int(key))
    if tba:
        return FileResponse(tba, media_type="image/png", headers=TBA_CACHE_HEADERS)
    raise HTTPException(status_code=404, detail="not found")
# #endregion


# #region public submission
@app.get("/submit", response_class=HTMLResponse)
def submit_page():
    return HTMLResponse(
        _submit_html(sorted(_events().items())), headers={"Cache-Control": "no-store"}
    )


@app.post("/submit")
async def submit(
    request: Request,
    team: int = Form(...),
    file: UploadFile = File(...),
    event: Optional[str] = Form(None),
):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="sign-in required")
    claims = verify_firebase_token(auth[7:])

    if team <= 0:
        raise HTTPException(status_code=400, detail="team must be a positive number")
    if not tba_team_exists(team):
        raise HTTPException(
            status_code=400, detail=f"team {team} not found on The Blue Alliance"
        )
    ev = _clean_event(event) if event else None
    if event and not ev:
        raise HTTPException(status_code=400, detail="invalid event code")

    try:
        img = Image.open(io.BytesIO(await file.read())).convert("RGBA")
    except Exception:
        raise HTTPException(status_code=400, detail="not a readable image")
    if img.width != img.height:
        raise HTTPException(
            status_code=400,
            detail=f"image must be square (got {img.width}x{img.height})",
        )

    pid = secrets.token_hex(8)
    _save_png(img, os.path.join(PENDING_DIR, f"{pid}.png"))
    meta = {
        "id": pid,
        "team": team,
        "event": ev,
        "name": claims["name"],
        "email": claims["email"],
        "uid": claims["uid"],
        "submitted_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(os.path.join(PENDING_DIR, f"{pid}.json"), "w") as f:
        json.dump(meta, f, indent=2)

    scope = f"event {ev}" if ev else "team default"
    who = claims["name"] or "someone"
    notify_discord(
        f"New avatar submission: team {team} ({scope}) from {who} "
        f"<{claims['email']}> -> {PUBLIC_BASE_URL}/admin/queue"
    )
    return JSONResponse({"ok": True, "team": team})
# #endregion


# #region protected portal
@app.post("/upload")
async def upload(
    team: int = Form(...),
    file: UploadFile = File(...),
    event: Optional[str] = Form(None),
    _: bool = Depends(require_auth),
):
    if team <= 0:
        raise HTTPException(status_code=400, detail="team must be a positive number")
    ev = _clean_event(event) if event else None
    if event and not ev:
        raise HTTPException(status_code=400, detail="invalid event code")
    try:
        _store(str(team), await file.read(), ev)
    except Exception:
        raise HTTPException(status_code=400, detail="not a readable image")
    return RedirectResponse("/admin", status_code=303)


@app.post("/upload-default")
async def upload_default(file: UploadFile = File(...), _: bool = Depends(require_auth)):
    try:
        _store(DEFAULT_KEY, await file.read())
    except Exception:
        raise HTTPException(status_code=400, detail="not a readable image")
    return RedirectResponse("/admin", status_code=303)


@app.post("/upload-zip", response_class=HTMLResponse)
async def upload_zip(
    file: UploadFile = File(...),
    event: Optional[str] = Form(None),
    _: bool = Depends(require_auth),
):
    ev = _clean_event(event) if event else None
    if event and not ev:
        raise HTTPException(status_code=400, detail="invalid event code")
    try:
        zf = zipfile.ZipFile(io.BytesIO(await file.read()))
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="not a valid zip file")

    saved: list = []
    skipped: list = []
    for name in zf.namelist():
        base = os.path.basename(name)  # ignore any directory structure
        if not base or base.startswith("."):
            continue
        stem, ext = os.path.splitext(base)
        if ext.lower() not in IMAGE_EXTS or not stem.isdigit():
            skipped.append(base)
            continue
        try:
            _store(stem, zf.read(name), ev)
            saved.append(int(stem))
        except Exception:
            skipped.append(base)

    return _zip_result_html(sorted(saved), skipped, ev)


@app.post("/delete")
def delete(
    team: int = Form(...),
    event: Optional[str] = Form(None),
    _: bool = Depends(require_auth),
):
    ev = _clean_event(event) if event else None
    p = _path(str(team), ev)
    if os.path.exists(p):
        os.remove(p)
    return RedirectResponse("/admin", status_code=303)


@app.post("/delete-default")
def delete_default(_: bool = Depends(require_auth)):
    if os.path.exists(_path(DEFAULT_KEY)):
        os.remove(_path(DEFAULT_KEY))
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/event/add")
def event_add(
    code: str = Form(...),
    name: Optional[str] = Form(None),
    _: bool = Depends(require_auth),
):
    ev = _clean_event(code)
    if not ev:
        raise HTTPException(status_code=400, detail="code must be lowercase alphanumeric")
    # No TBA/existence check: the admin registers codes deliberately (offseason or
    # custom events won't be in TBA, and submissions may target one not yet added).
    d = _events()
    d[ev] = {"name": (name or "").strip() or ev, "added": int(time.time())}
    _save_events(d)
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/event/delete")
def event_delete(code: str = Form(...), _: bool = Depends(require_auth)):
    ev = _clean_event(code)
    d = _events()
    if ev in d:
        del d[ev]
        _save_events(d)
    return RedirectResponse("/admin", status_code=303)


@app.get("/admin/queue", response_class=HTMLResponse)
def admin_queue(_: bool = Depends(require_auth)):
    items = []
    for pid in _pending_ids():
        try:
            items.append(_pending_meta(pid))
        except Exception:
            continue
    return _queue_html(items)


@app.get("/admin/pending/{pid}")
def admin_pending_img(pid: str, _: bool = Depends(require_auth)):
    pid = os.path.basename(pid)
    if pid.endswith(".png"):
        pid = pid[:-4]
    p = os.path.join(PENDING_DIR, f"{pid}.png")
    if not os.path.exists(p):
        raise HTTPException(status_code=404, detail="not found")
    return FileResponse(p, media_type="image/png", headers={"Cache-Control": "no-store"})


@app.post("/admin/queue/approve")
def queue_approve(id: str = Form(...), _: bool = Depends(require_auth)):
    pid = os.path.basename(id)
    meta = _pending_meta(pid)
    team = str(int(meta["team"]))
    ev = _clean_event(meta.get("event")) if meta.get("event") else None
    if ev and ev not in _events():  # keep the registry consistent
        d = _events()
        d[ev] = {"name": ev, "added": int(time.time())}
        _save_events(d)
    with open(os.path.join(PENDING_DIR, f"{pid}.png"), "rb") as f:
        _store(team, f.read(), ev)  # re-encode; robust across volume mounts
    _remove_pending(pid)
    return RedirectResponse("/admin/queue", status_code=303)


@app.post("/admin/queue/reject")
def queue_reject(id: str = Form(...), _: bool = Depends(require_auth)):
    _remove_pending(os.path.basename(id))
    return RedirectResponse("/admin/queue", status_code=303)


@app.get("/admin", response_class=HTMLResponse)
def portal(_: bool = Depends(require_auth)):
    return _portal_html(_teams())
# #endregion


# #region pending helpers
def _pending_ids() -> list:
    if not os.path.isdir(PENDING_DIR):
        return []
    return sorted(f[:-5] for f in os.listdir(PENDING_DIR) if f.endswith(".json"))


def _pending_meta(pid: str) -> dict:
    with open(os.path.join(PENDING_DIR, f"{pid}.json")) as f:
        return json.load(f)


def _remove_pending(pid: str) -> None:
    for ext in ("png", "json"):
        p = os.path.join(PENDING_DIR, f"{pid}.{ext}")
        if os.path.exists(p):
            os.remove(p)
# #endregion


# #region public landing page
@app.get("/", response_class=HTMLResponse)
def index(event: Optional[str] = None):
    ev = _clean_event(event) if event else None
    # Event view shows ONLY teams with an event-specific upload (no team-default
    # fallback - that's the intended UX). Default view = team defaults only.
    teams = sorted(_event_teams(ev)) if ev else _teams()
    return HTMLResponse(
        _public_html(teams, ev), headers={"Cache-Control": "public, max-age=60"}
    )
# #endregion


# #region HTML
def _dims(key: str, event: Optional[str] = None) -> str:
    try:
        with Image.open(_path(key, event)) as im:
            return f"{im.width}&times;{im.height}"
    except Exception:
        return "?"


def _event_options(selected: str = "") -> str:
    opts = ['<option value="">Team default</option>']
    for code, meta in sorted(_events().items()):
        name = meta.get("name", code)
        sel = " selected" if code == selected else ""
        opts.append(f'<option value="{code}"{sel}>{code} ({name})</option>')
    return "".join(opts)


def _portal_html(teams: list) -> str:
    pending_n = len(_pending_ids())
    events = _events()
    default_v = _version(DEFAULT_KEY)
    if default_v:
        default_block = f"""
      <div class="default-current">
        <img src="/avatar/default.png?s=96&v={default_v}" alt="default" />
        <div>
          <div class="dim">{_dims(DEFAULT_KEY)}</div>
          <form method="post" action="/delete-default" onsubmit="return confirm('Delete the default avatar?')">
            <button class="del" type="submit">Delete default</button>
          </form>
        </div>
      </div>"""
    else:
        default_block = '<p class="hint">No default avatar set. Teams without an upload use the display placeholder.</p>'

    event_rows = "".join(
        f"""
        <div class="event-row">
          <span><code>{code}</code> &middot; {meta.get('name', code)} &middot; {len(_event_teams(code))} avatar(s)</span>
          <form method="post" action="/admin/event/delete" onsubmit="return confirm('Remove event {code} from the registry? (uploaded avatars are kept)')">
            <input type="hidden" name="code" value="{code}" />
            <button class="del" type="submit">Remove</button>
          </form>
        </div>"""
        for code, meta in sorted(events.items())
    ) or '<p class="hint">No events registered yet.</p>'

    event_select = f'<label>Event<select name="event">{_event_options()}</select></label>'

    cards = "".join(
        f"""
        <figure>
          <img src="/avatar/{t}.png?s=96&v={_version(str(t))}" alt="Team {t}" />
          <figcaption>{t}<span class="dim">{_dims(str(t))}</span></figcaption>
          <form method="post" action="/delete" onsubmit="return confirm('Delete team {t} default avatar?')">
            <input type="hidden" name="team" value="{t}" />
            <button class="del" type="submit">Delete</button>
          </form>
        </figure>"""
        for t in teams
    )
    if not cards:
        cards = '<p class="empty">No avatars uploaded yet.</p>'
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Avatar Store</title>
{_STYLE}
</head>
<body>
<header>
  <h1>Avatar Store</h1>
  <p>Upload team avatars (any resolution). The audience display scales them and uses them in place of the blurry FMS avatars.</p>
  <p><a href="/admin/queue">Pending submissions ({pending_n})</a> &middot; <a href="/submit">Public submit page</a></p>
</header>
<main>
  <section class="upload">
    <h2>Events</h2>
    <p class="hint">Register a TBA-style event code (e.g. <code>2026mirr</code>) to upload event-specific avatars. Any lowercase alphanumeric code is accepted.</p>
    <form method="post" action="/admin/event/add" class="row">
      <label>Event code<input type="text" name="code" required placeholder="2026mirr" /></label>
      <label>Label (optional)<input type="text" name="name" placeholder="Michigan ..." /></label>
      <button type="submit">Add event</button>
    </form>
    <div class="events">{event_rows}</div>
  </section>
  <section class="upload">
    <h2>Upload one avatar</h2>
    <form method="post" action="/upload" enctype="multipart/form-data" class="row">
      <label>Team number
        <input type="number" name="team" min="1" required placeholder="254" />
      </label>
      {event_select}
      <label>Image
        <input type="file" name="file" accept="image/*" required
               onchange="const p=document.getElementById('preview'); if(this.files[0]){{p.src=URL.createObjectURL(this.files[0]); p.style.display='block';}}" />
      </label>
      <img id="preview" alt="preview" />
      <button type="submit">Upload</button>
    </form>
  </section>
  <section class="upload">
    <h2>Bulk upload (ZIP)</h2>
    <p class="hint">A .zip of image files each named for its team, e.g. <code>254.png</code>, <code>1678.png</code>. Any resolution; non-matching files are skipped. Choose an event to scope the whole batch.</p>
    <form method="post" action="/upload-zip" enctype="multipart/form-data" class="row">
      <label>Event<select name="event">{_event_options()}</select></label>
      <label>ZIP file
        <input type="file" name="file" accept=".zip,application/zip" required />
      </label>
      <button type="submit">Upload ZIP</button>
    </form>
  </section>
  <section class="upload">
    <h2>Default avatar</h2>
    <p class="hint">Shown for any team that has no avatar of its own (instead of the display's built-in placeholder).</p>
    {default_block}
    <form method="post" action="/upload-default" enctype="multipart/form-data" class="row">
      <label>Image
        <input type="file" name="file" accept="image/*" required />
      </label>
      <button type="submit">Set default</button>
    </form>
  </section>
  <section>
    <h2>Team default avatars ({len(teams)})</h2>
    <div class="grid">{cards}</div>
  </section>
</main>
</body>
</html>"""


def _queue_html(items: list) -> str:
    if items:
        cards = "".join(
            f"""
        <figure>
          <img src="/admin/pending/{it['id']}.png" alt="submission" />
          <figcaption>
            Team {it.get('team')}<span class="dim">{('event ' + it['event']) if it.get('event') else 'team default'}</span>
            <span class="dim">{it.get('name','')} &lt;{it.get('email','')}&gt;</span>
            <span class="dim">{(it.get('submitted_at','') or '')[:19].replace('T',' ')}</span>
          </figcaption>
          <div class="queue-actions">
            <form method="post" action="/admin/queue/approve">
              <input type="hidden" name="id" value="{it['id']}" />
              <button type="submit">Approve</button>
            </form>
            <form method="post" action="/admin/queue/reject" onsubmit="return confirm('Reject and delete this submission?')">
              <input type="hidden" name="id" value="{it['id']}" />
              <button class="del" type="submit">Reject</button>
            </form>
          </div>
        </figure>"""
            for it in items
        )
    else:
        cards = '<p class="empty">No pending submissions.</p>'
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Pending submissions</title>
{_STYLE}
</head>
<body>
<header>
  <h1>Pending submissions ({len(items)})</h1>
  <p><a href="/admin">&larr; Back to the portal</a></p>
</header>
<main>
  <div class="grid">{cards}</div>
</main>
</body>
</html>"""


def _submit_html(events_items: list) -> str:
    options = "".join(
        f'<option value="{code}">{code} ({meta.get("name", code)})</option>'
        for code, meta in events_items
    )
    # Only the public web config is injected; the apiKey is a client identifier,
    # not a secret. Built as its own tiny script so the main JS below needs no
    # f-string brace-escaping.
    config_script = (
        "<script>window.FB={"
        f'apiKey:"{FIREBASE_API_KEY}",'
        f'authDomain:"{FIREBASE_AUTH_DOMAIN}",'
        f'projectId:"{FIREBASE_PROJECT_ID}"'
        "};</script>"
    )
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\" />"
        '<meta name="viewport" content="width=device-width, initial-scale=1" />'
        "<title>Submit an FRC avatar</title>" + _STYLE + "</head><body>"
        "<header><h1>Submit a team avatar</h1>"
        "<p>Propose a crisp avatar for your team (or a specific event). Sign in with "
        "Google so we can credit the submission, then it goes to a short approval "
        "queue.</p></header>"
        "<main>"
        '<section class="upload">'
        '<div id="who" class="hint">Sign in to submit.</div>'
        '<button id="signin" type="button">Sign in with Google</button>'
        '<button id="signout" type="button" class="del" style="display:none">Sign out</button>'
        '<form id="form" style="display:none;margin-top:16px">'
        '<div class="row">'
        '<label>Team number<input type="number" name="team" min="1" required placeholder="254" /></label>'
        '<label>Event<select name="event"><option value="">Team default</option>'
        + options
        + "</select></label>"
        '<label>Image (must be square)<input type="file" name="file" id="file" accept="image/*" required /></label>'
        '<img id="preview" alt="preview" />'
        '<button type="submit">Submit for review</button>'
        "</div></form>"
        '<p id="msg" class="hint"></p>'
        "</section></main>"
        + config_script
        + '<script src="https://www.gstatic.com/firebasejs/10.12.0/firebase-app-compat.js"></script>'
        + '<script src="https://www.gstatic.com/firebasejs/10.12.0/firebase-auth-compat.js"></script>'
        + "<script>" + _SUBMIT_JS + "</script>"
        + "</body></html>"
    )


def _submit_done_html(team: int) -> str:  # unused (POST returns JSON) but kept for parity
    return f"<p>Thanks. Team {team} submission received.</p>"


def _public_html(teams: list, event: Optional[str] = None) -> str:
    events = _events()

    # Event selector: navigates to /?event=CODE (or / for the default view). A
    # page reload keeps it Cloudflare-cache-friendly (URL is the cache key).
    opts = [
        f'<option value=""{"" if event else " selected"}>All teams (default avatars)</option>'
    ]
    for code, meta in sorted(events.items()):
        name = meta.get("name", code)
        sel = " selected" if code == event else ""
        opts.append(f'<option value="{code}"{sel}>{code} ({name})</option>')
    selector = (
        '<div class="eventbar"><label>View event '
        "<select onchange=\"location = this.value ? '/?event=' + this.value : '/'\">"
        + "".join(opts)
        + "</select></label></div>"
    )

    default_v = _version(DEFAULT_KEY)
    cards = ""
    if default_v and not event:
        cards += (
            f'<a class="card-link" href="/avatar/default.png">'
            f'<figure><img src="/avatar/default.png?s=96&v={default_v}" alt="default" '
            f'loading="lazy" /><figcaption>default'
            f'<span class="dim">{_dims(DEFAULT_KEY)}</span></figcaption></figure></a>'
        )
    for t in teams:
        # Event view lists only teams that HAVE an event upload (no default
        # fallback), so `event` resolves to the event image here; default view
        # passes event=None and resolves to the team default.
        ver = _effective_version(t, event)
        dims = _dims(str(t), event)
        q = f"?s=96&v={ver}" + (f"&event={event}" if event else "")
        href = f"/avatar/{t}.png" + (f"?event={event}" if event else "")
        cards += (
            f'<a class="card-link" href="{href}">'
            f'<figure><img src="/avatar/{t}.png{q}" alt="Team {t}" '
            f'loading="lazy" /><figcaption>{t}'
            f'<span class="dim">{dims}</span></figcaption></figure></a>'
        )
    if not cards:
        cards = (
            '<p class="empty">No event-specific avatars for this event yet.</p>'
            if event
            else '<p class="empty">No avatars uploaded yet.</p>'
        )

    # Pre-escaped so it renders literally inside <pre>.
    examples = (
        "GET /avatars\n"
        '  &rarr; {"teams": {"254": 1712, ...}, "default": 1712, "events": ["2026mirr"]}\n\n'
        "GET /avatars?event=2026mirr     # effective versions for that event\n"
        "GET /avatar/254.png?s=160       # a team avatar, scaled to 160px (s = 16..1024)\n"
        "GET /avatar/254.png?event=2026mirr&s=160   # event avatar, else team default, else TBA\n"
        "GET /avatar/default.png?s=160   # fallback avatar for teams with no upload\n\n"
        "# drop the ?s= to get the original full-resolution image\n"
        "# add &amp;v=&lt;version from /avatars&gt; so a re-upload busts the cache\n\n"
        f'&lt;img src="{PUBLIC_BASE_URL}/avatar/254.png?s=160"&gt;'
    )

    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\" />"
        '<meta name="viewport" content="width=device-width, initial-scale=1" />'
        "<title>FRC Avatar Store</title>" + _STYLE + "</head><body>"
        "<header><h1>FRC Avatar Store</h1>"
        "<p>Crisp team avatars for the audience display, served by team number and event.</p>"
        '<p><a href="/submit">Submit an avatar for your team &rarr;</a></p></header>'
        "<main>"
        '<section class="api"><h2>API</h2>'
        f'<p>Base URL <code>{PUBLIC_BASE_URL}</code> &middot; CORS-enabled &middot; '
        "Cloudflare-cached &middot; use any endpoint directly as an <code>&lt;img src&gt;</code>.</p>"
        "<pre>" + examples + "</pre></section>"
        "<section>"
        + (
            f"<h2>Avatars for {event} ({len(teams)})</h2>"
            if event
            else f"<h2>Uploaded avatars ({len(teams)})</h2>"
        )
        + selector
        + '<div class="grid">'
        + cards
        + "</div></section>"
        '<footer><a href="/admin">Manage avatars &rarr;</a> (sign-in required)</footer>'
        "</main></body></html>"
    )


def _zip_result_html(saved: list, skipped: list, event: Optional[str]) -> str:
    saved_txt = ", ".join(str(t) for t in saved) or "none"
    skipped_txt = ", ".join(skipped) or "none"
    scope = f"event {event}" if event else "team default"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>ZIP upload</title>{_STYLE}</head>
<body>
<header><h1>ZIP upload complete ({scope})</h1></header>
<main>
  <p><strong>Saved {len(saved)}:</strong> {saved_txt}</p>
  <p><strong>Skipped {len(skipped)}:</strong> {skipped_txt}</p>
  <p><a href="/admin">&larr; Back to the portal</a></p>
</main>
</body></html>"""


_SUBMIT_JS = """
firebase.initializeApp(window.FB);
const auth = firebase.auth();
const provider = new firebase.auth.GoogleAuthProvider();
const $ = (id) => document.getElementById(id);
const msg = (t, err) => { $('msg').textContent = t; $('msg').style.color = err ? '#ff9a9a' : '#9aa4b2'; };

$('signin').onclick = () => auth.signInWithPopup(provider).catch((e) => msg(e.message, true));
$('signout').onclick = () => auth.signOut();

// Preview the chosen image and require it to be square (the server enforces this
// too, but check up front so the user is not surprised after submitting).
let squareOk = false;
$('file').onchange = () => {
  const f = $('file').files[0];
  $('preview').style.display = 'none';
  squareOk = false;
  if (!f) return;
  const url = URL.createObjectURL(f);
  const probe = new Image();
  probe.onload = () => {
    $('preview').src = url;
    $('preview').style.display = 'block';
    squareOk = probe.naturalWidth === probe.naturalHeight;
    msg(
      squareOk
        ? ''
        : `Image must be square: yours is ${probe.naturalWidth}x${probe.naturalHeight}.`,
      !squareOk
    );
  };
  probe.onerror = () => msg('That file is not a readable image.', true);
  probe.src = url;
};

auth.onAuthStateChanged((u) => {
  if (u) {
    $('who').textContent = 'Signed in as ' + (u.displayName || u.email);
    $('signin').style.display = 'none';
    $('signout').style.display = '';
    $('form').style.display = '';
  } else {
    $('who').textContent = 'Sign in to submit.';
    $('signin').style.display = '';
    $('signout').style.display = 'none';
    $('form').style.display = 'none';
  }
});

$('form').onsubmit = async (e) => {
  e.preventDefault();
  const user = auth.currentUser;
  if (!user) { msg('Sign in first.', true); return; }
  if (!squareOk) { msg('Image must be square (width = height).', true); return; }
  msg('Submitting...');
  try {
    const token = await user.getIdToken();
    const res = await fetch('/submit', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + token },
      body: new FormData($('form')),
    });
    const j = await res.json().catch(() => ({}));
    if (res.ok) {
      $('form').reset();
      $('preview').style.display = 'none';
      msg('Thanks! Your submission is queued for review.');
    } else {
      msg(j.detail || ('Error ' + res.status), true);
    }
  } catch (err) {
    msg(err.message, true);
  }
};
"""


_STYLE = """<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { font-family: system-ui, sans-serif; margin: 0; background: #14171c; color: #e8ecf1; }
  header { padding: 24px; border-bottom: 1px solid #2a2f38; }
  h1 { margin: 0; font-size: 22px; }
  header p { margin: 6px 0 0; color: #9aa4b2; font-size: 14px; }
  main { max-width: 960px; margin: 0 auto; padding: 24px; }
  a { color: #6ea8fe; }
  code { background: #0f1216; padding: 1px 6px; border-radius: 5px; }
  pre { background: #0f1216; border: 1px solid #2a2f38; border-radius: 10px; padding: 16px; overflow-x: auto; font-size: 13px; line-height: 1.6; color: #cdd6e0; }
  .api { background: #1b1f26; border: 1px solid #2a2f38; border-radius: 12px; padding: 20px; margin-bottom: 22px; }
  .api h2 { margin: 0 0 10px; font-size: 16px; }
  .api p { margin: 0 0 14px; color: #9aa4b2; font-size: 14px; }
  footer { margin-top: 28px; padding-top: 18px; border-top: 1px solid #2a2f38; color: #9aa4b2; font-size: 14px; }
  a.dim { text-decoration: none; }
  a.dim:hover { color: #e8ecf1; text-decoration: underline; }
  .upload { background: #1b1f26; border: 1px solid #2a2f38; border-radius: 12px; padding: 20px; margin-bottom: 22px; }
  .upload h2 { margin: 0 0 14px; font-size: 16px; }
  .hint { margin: -6px 0 14px; color: #9aa4b2; font-size: 13px; }
  .row { display: flex; gap: 12px; flex-wrap: wrap; align-items: end; }
  label { display: flex; flex-direction: column; gap: 6px; font-size: 13px; color: #9aa4b2; }
  input[type=number], input[type=text], input[type=file], select { background: #0f1216; border: 1px solid #333a45; color: #e8ecf1; border-radius: 8px; padding: 9px 11px; font-size: 14px; }
  input[type=number] { width: 130px; }
  button { background: #3b82f6; color: white; border: 0; border-radius: 8px; padding: 10px 16px; font-size: 14px; font-weight: 600; cursor: pointer; }
  button:hover { background: #2f6fe0; }
  #preview { width: 64px; height: 64px; border-radius: 8px; background: #0f1216; border: 1px solid #333a45; image-rendering: pixelated; object-fit: contain; display: none; }
  .default-current { display: flex; gap: 14px; align-items: center; margin-bottom: 14px; }
  .default-current img { width: 72px; height: 72px; object-fit: contain; background: #0f1216; border-radius: 8px; }
  .events { display: flex; flex-direction: column; gap: 8px; margin-top: 8px; }
  .event-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; background: #0f1216; border: 1px solid #2a2f38; border-radius: 8px; padding: 8px 12px; font-size: 14px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(120px, 1fr)); gap: 16px; }
  a.card-link { text-decoration: none; color: inherit; display: block; }
  a.card-link figure { transition: border-color 0.12s; height: 100%; }
  a.card-link:hover figure { border-color: #3b82f6; }
  figure { margin: 0; background: #1b1f26; border: 1px solid #2a2f38; border-radius: 12px; padding: 12px; text-align: center; }
  figure img { width: 96px; height: 96px; object-fit: contain; background: #0f1216; border-radius: 8px; }
  figcaption { margin: 8px 0; font-weight: 600; }
  .dim { display: block; font-weight: 400; font-size: 12px; color: #9aa4b2; }
  .queue-actions { display: flex; gap: 8px; justify-content: center; }
  .del { background: #3a2126; color: #ff9a9a; font-size: 12px; padding: 6px 10px; }
  .del:hover { background: #52272e; }
  .empty { color: #9aa4b2; }
  .eventbar { margin: 0 0 16px; }
  .eventbar label { font-weight: 600; color: #9aa4b2; font-size: 14px; }
  .eventbar select { margin-left: 8px; background: #1b1f26; color: #e8ecf1; border: 1px solid #2a2f38; border-radius: 8px; padding: 6px 10px; font: inherit; }
  .badge { display: inline-block; margin-left: 6px; padding: 1px 7px; border-radius: 999px; font-size: 11px; font-weight: 700; vertical-align: middle; background: #2a2f38; color: #7fd0a0; }
</style>"""
