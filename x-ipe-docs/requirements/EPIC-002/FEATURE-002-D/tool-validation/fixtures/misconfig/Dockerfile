# Self-authored misconfiguration fixture (FEATURE-002-D tool-level validation)
FROM python:latest
ADD app.py /app/app.py
RUN apt-get update && apt-get install -y curl
EXPOSE 22
CMD ["python", "/app/app.py"]
