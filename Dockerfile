FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY operator/main.py .
CMD ["kopf", "run", "--all-namespaces", "--standalone", "main.py"]