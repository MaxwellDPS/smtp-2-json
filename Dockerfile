FROM python:3.10-slim

LABEL maintainer="Your Name <your.email@example.com>"
LABEL description="SMTP server that converts emails to JSON"

# Set working directory
WORKDIR /app

# Install dependencies
COPY src/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/smtp_json_server.py .

# Expose SMTP port
EXPOSE 8025

# Create volume for email output
VOLUME ["/app/emails"]

# Set default command
ENTRYPOINT ["python", "smtp_json_server.py"]

# Default arguments (can be overridden via docker run command)
CMD ["--host", "0.0.0.0", "--port", "8025", "--output-dir", "/app/emails"]