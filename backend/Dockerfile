FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app/backend
WORKDIR /app
COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY --chown=10001:10001 backend /app/backend
USER 10001:10001
EXPOSE 8000
CMD ["sh", "-c", "python -m database.create_tables && exec uvicorn main:app --host 0.0.0.0 --port 8000"]
