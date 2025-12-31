FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

# Copy requirements first (better caching)
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Copy everything else
COPY . .

# Hugging Face requires port 7860
EXPOSE 7860

# Start Flask
CMD ["python", "app.py"]
