## HAProxy with features like: source-based rate limiting, DDoS prevention, XSS prevention, CORS configuration, OWASP security headers, and HTTP/2 support.

### Step 1: Install HAProxy

If you haven’t installed HAProxy yet, you can do it via the package manager for your operating system. For example, on Ubuntu, you can run:

```bash
sudo apt update
sudo apt install haproxy
```

### Step 2: Create Configuration Files

Create a new configuration file for HAProxy, typically located at `/etc/haproxy/haproxy.cfg`. You can copy the provided configuration template below.

#### Example HAProxy Configuration

```ini
global
    log /dev/log    local0
    log /dev/log    local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

    # Load Lua CORS Library
    lua-load /etc/haproxy/cors.lua

    # Default SSL material locations
    ca-base /etc/ssl/certs
    crt-base /etc/ssl/private

    # SSL configuration
    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets

defaults
    log     global
    mode    http
    option  httplog
    option  dontlognull
    timeout connect 5000
    timeout client  50000
    timeout server  50000
    errorfile 400 /etc/haproxy/errors/400.http
    errorfile 403 /etc/haproxy/errors/403.http
    errorfile 408 /etc/haproxy/errors/408.http
    errorfile 500 /etc/haproxy/errors/500.http
    errorfile 502 /etc/haproxy/errors/502.http
    errorfile 503 /etc/haproxy/errors/503.http
    errorfile 504 /etc/haproxy/errors/504.http

frontend https_front
    bind *:443 ssl crt /etc/ssl/private/my.domain.com.pem alpn h2,http/1.1
    mode http
    option forwardfor
    http-request set-header X-Forwarded-Proto: https
    default_backend web_backend

    # DDoS & Rate Limiting
    stick-table type ip size 1m expire 30s store http_req_rate(30s),conn_cur

    acl abuse src_http_req_rate(https_front) gt 100
    acl too_many_conns src_conn_cur gt 10

    http-request deny if abuse
    tcp-request content reject if too_many_conns
    http-request track-sc0 src
    http-request deny deny_status 429 if { sc_http_req_rate(0) gt 20 }

    # Security Headers (OWASP)
    http-response set-header X-Frame-Options "DENY"
    http-response set-header X-Content-Type-Options "nosniff"
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains"
    http-response set-header Referrer-Policy "no-referrer"
    http-response set-header Content-Security-Policy "default-src 'self'; script-src 'self';"
    http-response set-header X-XSS-Protection "1; mode=block"

    # CORS Configuration
    acl is_preflight_options method OPTIONS
    http-request capture req.hdr(Origin) len 20

    acl allowed_host1 hdr(host) -i example.com
    acl allowed_host2 hdr(host) -i example.org
    acl allowed_host3 hdr(host) -i example.ai
    http-request deny if !allowed_host1 !allowed_host2 !allowed_host3

backend web_backend
    mode http
    server local_server localhost:8000 check
```

### Step 3: Create Lua CORS File

Ensure you have a `cors.lua` file at the specified location. The content of this file might look something like this:

```lua
core.register_service("cors", "http", function(applet)
    applet:set_header("Access-Control-Allow-Origin", applet.headers["Origin"])
    applet:set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    applet:set_header("Access-Control-Allow-Headers", "Content-Type")
    applet:send()
end)
```

### Step 4: Create Custom Error Pages (Optional)

You can create custom error pages by placing HTML files in the `/etc/haproxy/errors` directory as specified in your configuration. For example, create `400.http`, `403.http`, etc.

```html
<!-- Example for 400.http -->
HTTP/1.1 400 Bad Request
Content-Type: text/html

<!DOCTYPE html>
<html>
<head>
    <title>400 Bad Request</title>
</head>
<body>
    <h1>400 Bad Request</h1>
    <p>Your request could not be understood by the server.</p>
</body>
</html>
```

### Step 5: Start HAProxy

Once everything is configured, you can start HAProxy. You might want to use a system service to manage HAProxy, or run it manually:

```bash
sudo service haproxy start
```

### Step 6: Verify HAProxy Configuration

Before starting HAProxy, ensure that the configuration file is valid:

```bash
sudo haproxy -c -f /etc/haproxy/haproxy.cfg
```

### Step 7: Monitor HAProxy Stats

To monitor HAProxy stats, ensure that your configuration allows access to the stats socket. You can access the stats socket via command line:

```bash
echo "show stat" | sudo socat stdio /run/haproxy/admin.sock
```

You may also configure a dedicated frontend for stats if desired.

### Additional Notes

- **Testing**: Test the configuration thoroughly to ensure all features (CORS, rate limiting, headers) are functioning as expected.
- **Logs**: Monitor logs to analyze traffic and errors for tuning performance.
- **Updates**: Keep your HAProxy updated to benefit from the latest security patches and features.

### Conclusion

This guide should provide a comprehensive framework for setting up HAProxy with the desired features. Adjust the configurations as necessary for your environment and specific requirements. Let me know if you need any more assistance!
