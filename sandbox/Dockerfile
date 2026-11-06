FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY runner.py /app/runner.py
COPY server.py /app/server.py
USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["python", "/app/server.py"]
