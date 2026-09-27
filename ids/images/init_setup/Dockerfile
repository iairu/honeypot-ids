# init_setup's tools, installed once at build time instead of by an
# `apk add` at the top of its command on every `docker compose up`.
# init_setup gates every other service, so that per-boot package download
# sat on the critical path of each start (and made a start fail outright
# whenever the Alpine mirror was unreachable). Rebuild to pick up package
# updates: `docker compose build --pull init_setup`.
FROM alpine:latest
RUN apk add --no-cache rsync openssl
