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

# Copy configuration files
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY lua/ /etc/nginx/lua/
COPY proxy_params /etc/nginx/proxy_params

# Set proper permissions
RUN chown -R nobody:nobody /var/log/nginx /var/cache/nginx

# Expose ports
EXPOSE 80 443

# Start nginx
CMD ["/usr/local/openresty/bin/openresty", "-g", "daemon off;"]