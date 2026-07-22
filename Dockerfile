FROM python:3.11-slim

WORKDIR /app

# Install system utilities (DNS utilities, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsutils \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy backend dependencies
COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY backend /app/backend
COPY frontend /app/frontend

WORKDIR /app/backend

# Hugging Face Spaces uses port 7860 by default
EXPOSE 7860

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "7860"]
