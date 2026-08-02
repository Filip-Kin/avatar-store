FROM python:3.10-slim

# uv (Astral) instead of pip: faster, better resolver.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

WORKDIR /app
ENV UV_SYSTEM_PYTHON=1

RUN uv pip install \
        fastapi==0.110.0 "uvicorn[standard]==0.29.0" \
        python-multipart==0.0.9 Pillow==10.2.0 \
        httpx==0.27.0 "PyJWT[crypto]==2.8.0"

COPY app.py .

ENV UPLOAD_DIR=/uploads
EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
