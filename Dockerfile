FROM python:3.10-slim

WORKDIR /app

# Install runtime dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose decoy ports for honeypot behavior (port mapping in docker-compose)
EXPOSE 21 22 80 8080

ENV HONEYPOT_PORTS="21,22,80,8080"
ENV LOG_LEVEL="INFO"

# Default command to run the simulation
CMD ["python", "honeypot_app.py"]
