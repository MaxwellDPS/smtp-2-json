# Docker and Environment Configuration Guide for SMTP to JSON Server

This guide explains how to use the Docker setup and environment variables for the SMTP to JSON Server.

## Docker Setup

### Prerequisites
- Docker installed on your system
- Docker Compose (optional, for using docker-compose.yml)

### Building the Docker Image Locally

1. Make sure all files are in the same directory:
   - `smtp_json_server.py` (your main application)
   - `requirements.txt`
   - `Dockerfile`

2. Build the image:
   ```bash
   docker build -t smtp-json-server:latest .
   ```

3. Run the container with your webhook URL:
   ```bash
   docker run -p 8025:8025 -e WEBHOOK_URL=https://your-webhook.com/emails smtp-json-server:latest
   ```

### Using Docker Compose

For easier management, you can use Docker Compose:

1. Update the `docker-compose.yml` file with your actual webhook URL and API key:
   ```yaml
   environment:
     - WEBHOOK_URL=https://your-actual-webhook.com/endpoint
     - API_KEY=your_actual_api_key
   ```

2. Start the service:
   ```bash
   docker-compose up -d
   ```

This will start the SMTP server in detached mode, exposing port 8025.

### Environment Variable Configuration

The application supports the following environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `SMTP_HOST` | Hostname for SMTP server to bind to | `0.0.0.0` |
| `SMTP_PORT` | Port for SMTP server to listen on | `8025` |
| `WEBHOOK_URL` | URL to POST email JSON data (required) | *None* |
| `API_KEY` | API key for webhook authentication (optional) | *None* |
| `LOG_LEVEL` | Logging level (DEBUG, INFO, WARNING, ERROR) | `INFO` |

### Using a .env File for Local Development

You can create a `.env` file for local development:

```
SMTP_HOST=0.0.0.0
SMTP_PORT=8025
WEBHOOK_URL=https://webhook.site/your-unique-id
API_KEY=test_key_123
LOG_LEVEL=DEBUG
```

## GitHub CI Workflow

The included GitHub Actions workflow automates building and publishing your Docker image to GitHub Container Registry (ghcr.io).

### Setup Steps

1. Create the `.github/workflows` directory in your repository:
   ```bash
   mkdir -p .github/workflows
   ```

2. Place the `docker-build.yml` file in this directory.

3. Commit and push to your GitHub repository:
   ```bash
   git add .
   git commit -m "Add Docker and CI configuration"
   git push
   ```

### Workflow Behavior

- The workflow runs on:
  - Pushes to main/master branches
  - Creation of tags starting with "v" (e.g., v1.0.0)
  - Pull requests to main/master branches

- For pushes to the main branch, it builds and pushes the image with the "latest" tag
- For tagged releases, it creates versioned tags (e.g., v1.0.0, v1.0, v1)
- For pull requests, it builds but doesn't push the image

### Using the Published Image

After the workflow successfully runs on your main branch or a tag, you can pull and run your image from GitHub Container Registry:

```bash
# Pull the image (replace 'username/repo' with your GitHub username and repository name)
docker pull ghcr.io/username/repo:latest

# Run the image
docker run -p 8025:8025 -v $(pwd)/emails:/app/emails ghcr.io/username/repo:latest
```

### Secrets and Permissions

The workflow uses the automatic `GITHUB_TOKEN` provided by GitHub Actions for authentication. This token has permissions to push packages to the GitHub Container Registry for your repository.

If you want to publish to Docker Hub instead, you'll need to modify the workflow to use Docker Hub credentials stored as GitHub repository secrets.