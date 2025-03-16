FROM python:3.10-slim

LABEL maintainer="Your Name <your.email@example.com>"
LABEL description="SMTP server that converts emails to JSON"

# Set working directory
WORKDIR /app

# Set environment variables with defaults
ENV SMTP_HOST=0.0.0.0 \
    SMTP_PORT=8025 \
    WEBHOOK_URL="" \
    API_KEY="" \
    LOG_LEVEL="INFO"

# Install dependencies
COPY src/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/smtp_json_server.py .

# Expose SMTP port
EXPOSE 8025

# Set default command
ENTRYPOINT ["python", "smtp_json_server.py"]

