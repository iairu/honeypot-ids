FROM openresty/openresty:alpine

# Install additional packages including perl for opm
# ca-certificates is required for resty.http's ssl_verify=true to succeed on
# outbound HTTPS calls (AbuseIPDB API in abuseipdb_client.lua) -- without it
# every request fails with "unable to get local issuer certificate".
RUN apk add --no-cache \
    curl \
    jq \
    openssl \
    git \
    perl \
    make \
    ca-certificates

# docker-compose.yml bind-mounts host directories over BOTH /etc/nginx and
# /etc/ssl/certs at runtime (for the Lua modules and server.crt/server.key
# respectively), which shadows whatever apk installed under either path --
# including the CA bundle just installed above. /usr/local/openresty is not
# mounted over by anything, so the bundle is copied there instead where
# lua_ssl_trusted_certificate (nginx.conf) can still find it at runtime.
RUN cp /etc/ssl/certs/ca-certificates.crt /usr/local/openresty/ca-certificates.crt

# Install OpenResty packages using opm
RUN /usr/local/openresty/bin/opm get ledgetech/lua-resty-http

# Create directories
RUN mkdir -p /var/log/nginx /etc/nginx/lua /etc/ssl/certs /var/cache/nginx/static

# Copy configuration files. These paths are ALSO covered by
# docker-compose.yml's `./reverse_proxy_enhanced:/etc/nginx` bind mount at
# runtime, so this COPY only matters if the image is ever run without that
# mount (e.g. a bare `docker run`); with the mount, the host files win.
COPY lua/ /etc/nginx/lua/
COPY proxy_params /etc/nginx/proxy_params

# Set proper permissions
RUN chown -R nobody:nobody /var/log/nginx /var/cache/nginx

# Expose ports
EXPOSE 80 443

# Start nginx, pointed explicitly at /etc/nginx/nginx.conf.
#
# nginx.conf itself deliberately has NO COPY into the image (unlike lua/ and
# proxy_params above). It used to be COPY'd to OpenResty's own default
# config path (/usr/local/openresty/nginx/conf/nginx.conf), which is where
# `openresty -g "daemon off;"` looks by default when no -c flag is given.
# Since that's a DIFFERENT path than /etc/nginx/nginx.conf (the one the
# compose bind mount actually updates live), every nginx.conf edit this
# session was silently invisible to the running process -- `nginx -s
# reload`/`docker compose restart` kept re-reading the stale image-build-
# time copy, not the live file being edited. A change only ever took effect
# if the image happened to be rebuilt afterward, which is not what "nginx
# -s reload" implies it does. Explicit -c here makes the bind-mounted file
# authoritative, matching how every other file in this image already
# behaves (lua/, proxy_params) and how a reload was always assumed to work.
CMD ["/usr/local/openresty/bin/openresty", "-c", "/etc/nginx/nginx.conf", "-g", "daemon off;"]