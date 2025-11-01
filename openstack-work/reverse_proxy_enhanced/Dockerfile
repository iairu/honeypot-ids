FROM openresty/openresty:alpine

# Install additional packages
RUN apk add --no-cache \
    curl \
    jq \
    openssl \
    git

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