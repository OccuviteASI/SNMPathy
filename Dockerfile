# SNMPathy container image
#   docker build -t snmpathy .
#   docker run -d -p 8080:8080 -p 514:5514/udp -p 514:5514/tcp -v snmpathy-data:/data snmpathy
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SNMPATHY_DATABASE=/data/snmpathy.db \
    SNMPATHY_HTTP_HOST=0.0.0.0 \
    SNMPATHY_HTTP_PORT=8080 \
    SNMPATHY_SYSLOG_UDP_PORT=5514 \
    SNMPATHY_SYSLOG_TCP_PORT=5514

# iputils-ping is the ICMP fallback when raw sockets are not permitted.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY snmpathy ./snmpathy
RUN pip install .

# Run unprivileged. Raw ICMP needs CAP_NET_RAW (granted to containers by
# default); docker-compose.yml additionally enables unprivileged ICMP sockets.
RUN useradd --system --uid 10001 --home-dir /data snmpathy \
    && mkdir -p /data && chown snmpathy /data
USER snmpathy
VOLUME ["/data"]

EXPOSE 8080 5514/udp 5514/tcp
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4).status == 200 else 1)"

CMD ["snmpathy", "serve"]
