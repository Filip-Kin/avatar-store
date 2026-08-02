# avatar-store

A small FastAPI service that hosts hand-made, crisp FRC team avatars for an
audience display, in place of the blurry 40px avatar FMS provides.

Avatars resolve in three tiers for a given team at a given event:

1. **event upload** `uploads/events/{event}/{team}.png` (crisp, event-branded)
2. **team default** `uploads/{team}.png` (crisp, the team's normal avatar)
3. **TBA low-res** the ~40px avatar from The Blue Alliance (pixelated fallback)

The public can propose avatars at `/submit` (Google sign-in via Firebase, team
number validated against The Blue Alliance). Submissions land in a pending queue
and the admin is pinged on Discord to approve or reject them at `/admin/queue`.

## Endpoints

Reads are public; the `.png` suffix lets a CDN edge-cache them.

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/health` | status + counts |
| GET | `/avatars[?event=CODE]` | `{teams:{num:ver}, default, events:[...]}` |
| GET | `/avatar/{team}.png[?event=&s=&v=]` | event → team default → TBA → 404 |
| GET | `/avatar/default.png[?s=]` | the shared default avatar |
| GET | `/submit` | public submission page (Google sign-in) |
| POST | `/submit` | queue a proposal (`Authorization: Bearer <firebase id token>`) |
| GET | `/` | public landing page |
| GET | `/admin`, `/admin/queue` | manage portal + approval queue (auth) |
| POST | `/upload`, `/upload-default`, `/upload-zip`, `/delete`, `/delete-default` | auth |
| POST | `/admin/event/add`, `/admin/event/delete` | register/remove event codes (auth) |
| POST | `/admin/queue/approve`, `/admin/queue/reject` | auth |

`v` is the file mtime, so a re-upload becomes a fresh URL (instant update) while
responses stay long-cached. Admin auth is Authelia forward-auth (the `Remote-User`
header) with an HTTP Basic fallback for direct container access.

## Running

```sh
cp .env.example .env   # fill in the values
docker compose up -d --build
```

Scaled variants (`?s=N`, 16-1024) are generated on request and cached; originals
are kept at full uploaded resolution.
