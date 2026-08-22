#!/bin/bash
set -e
echo "Starting ARGUS LLM Security Gateway..."
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
