# Configuration Files

This directory contains all configuration files for the FAF project.

## Docker Configuration
- `Dockerfile` - Main Docker image configuration
- `docker-compose.yml` - Production Docker Compose setup
- `docker-compose.dev.yml` - Development Docker Compose setup
- `.dockerignore` - Files to exclude from Docker build

## Environment Configuration
- `.env.example` - Template for environment variables
- `render-env-template.txt` - Render.com environment template
- `render.yaml` - Render.com deployment configuration

## Usage
Copy `.env.example` to `.env` and configure your environment variables before running the application.