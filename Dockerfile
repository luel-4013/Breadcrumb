FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    BREADCRUMB_HOST=0.0.0.0 \
    BREADCRUMB_PORT=8787 \
    BREADCRUMB_RELOAD=0 \
    BREADCRUMB_DB_PATH=/data/breadcrumb.db

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY run.py .

EXPOSE 8787
VOLUME /data
CMD ["python", "run.py"]
