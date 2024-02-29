FROM python:3.12-slim

WORKDIR /app
COPY . /app

RUN apt-get update && \
    apt-get install -y libtool libjansson-dev libmagic-dev libssl-dev yara curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    pip install --no-cache-dir -r requirements.txt






