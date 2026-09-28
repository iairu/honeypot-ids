# backup_service's mysqldump/mysql clients, installed once at build time
# instead of by an `apk add` on every container start. Rebuild to pick up
# package updates: `docker compose build --pull backup_service`.
FROM alpine:latest
RUN apk add --no-cache mysql-client
