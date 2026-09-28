FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi uvicorn httpx pydantic

COPY target_app.py .
COPY test_users.json .
COPY synthetic_data.json .

EXPOSE 8080

CMD ["python", "target_app.py"]
