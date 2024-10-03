FROM haproxy:2.4-bookworm

# Switch to root user to create necessary directories
USER root

# Create the necessary directory for chroot
RUN mkdir -p /var/lib/haproxy && chown haproxy:haproxy /var/lib/haproxy

# Create the necessary directory for the admin socket
RUN mkdir -p /run/haproxy && chown haproxy:haproxy /run/haproxy

# Switch back to haproxy user
USER haproxy

COPY haproxy.cfg /usr/local/etc/haproxy/haproxy.cfg
COPY cors.lua /usr/local/etc/haproxy/cors.lua
COPY errors /usr/local/etc/haproxy/errors
