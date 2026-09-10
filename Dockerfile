FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY protectarr ./protectarr
COPY run.py .

# Config is expected at /config/config.yaml (mount a volume there).
ENV PROTECTARR_CONFIG=/config/config.yaml
VOLUME ["/config"]
EXPOSE 8090

CMD ["python", "run.py"]
