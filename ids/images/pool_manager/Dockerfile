# pool_manager: builds and retires honeypot pool containers
# (honeypot_eshop_N + honeypot_database_N) on demand through the Docker API.
# Also its own helper image: seeding steps run as short-lived containers of
# this same image, which is why rsync is installed.
FROM python:3.12-alpine
RUN apk add --no-cache rsync tar \
 && pip install --no-cache-dir docker==7.1.0 redis==5.0.8
WORKDIR /app
COPY pool_logic.py manager.py ./
CMD ["python", "-u", "manager.py"]
