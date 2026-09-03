FROM python:3.12-slim

# yara-python needs libyara at build time on some platforms; the wheel
# usually ships prebuilt, but keep build-essential for a reliable fallback.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

COPY . .

RUN mkdir -p reports config \
    && [ -f config/config.yaml ] || cp config/config.example.yaml config/config.yaml

EXPOSE 5000

# Default: run the web UI. Override the command to use the CLI instead, e.g.:
#   docker run --rm -v $(pwd)/samples:/app/samples phishing-investigation-platform \
#     python main.py --input samples/phish.eml
CMD ["gunicorn", "--chdir", "webapp", "--bind", "0.0.0.0:5000", "app:app"]
