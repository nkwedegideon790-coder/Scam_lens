# FastAPI backend with Tesseract OCR. Deploy to Render, Railway, Fly.io, Cloud Run, etc.
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-eng \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements-backend.txt .
RUN pip install --no-cache-dir -r requirements-backend.txt

COPY backend ./backend
RUN mkdir -p /app/data

ENV PORT=8000 SCAMLENS_DB_PATH=/app/data/scamlens.db
EXPOSE 8000
CMD ["sh", "-c", "uvicorn backend.main:app --host 0.0.0.0 --port ${PORT}"]
