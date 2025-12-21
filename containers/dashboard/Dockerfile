FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY dashboard.py .
COPY templates ./templates/

EXPOSE 80

CMD ["python", "dashboard.py"]
