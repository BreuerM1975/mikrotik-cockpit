# MikroTik Cockpit in a container. Build from the repository root:
#   docker compose up --build -d      then open http://<docker-host>:8787/
# The image contains the same code you would run with ./start-cockpit.sh. Router credentials
# are entered per browser session and never stored in the image; backups, known_hosts and the
# device/room mapping live in the /data volume.
FROM python:3.12-slim

# ssh/scp/ssh-keyscan/ssh-keygen talk to the router, sshpass passes the session password,
# wg generates WireGuard keys (Pro). Nothing else is needed at runtime.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client sshpass wireguard-tools \
 && apt-get clean \
 && useradd --create-home --uid 1000 cockpit \
 && mkdir -p /data && chown cockpit:cockpit /data && chmod 700 /data

WORKDIR /opt/cockpit
COPY app/backend/requirements.txt app/backend/requirements.txt
RUN pip install --no-cache-dir -r app/backend/requirements.txt
COPY app/ app/

# Cockpit refuses data directories that are not private (0700, owned by its own user), so the
# volume must be created from this image (a named volume does that; a bind mount needs
# "chown 1000:1000 && chmod 700" once).
ENV COCKPIT_BIND_HOST=0.0.0.0 \
    COCKPIT_BACKEND_PORT=8787 \
    COCKPIT_BACKUP_DIR=/data/backups \
    COCKPIT_DEVICE_ROOMS_DIR=/data/device-rooms \
    COCKPIT_KNOWN_HOSTS_FILE=/data/known_hosts \
    PYTHONUNBUFFERED=1

USER cockpit
VOLUME ["/data"]
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/', timeout=3)" || exit 1
CMD ["python", "app/backend/src/app.py"]
