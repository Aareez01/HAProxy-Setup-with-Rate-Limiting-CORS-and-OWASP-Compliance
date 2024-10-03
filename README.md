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

        # See: https://ssl-config.mozilla.org/#server=haproxy&server-version=2.0.3&config=intermediate
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
    bind *:443 ssl crt /etc/ssl/private/domain.example.com.pem alpn h2,http/1.1
    mode http
    option forwardfor
    http-request set-header X-Forwarded-Proto: https
    default_backend web_backend

    # DDoS & Rate Limiting
    # Allows HAProxy to track statistics (like request rates, current connections, etc.) per IP address. This is useful for applying rate limits or connection limits.
    stick-table type ip size 1m expire 30s store http_req_rate(30s),conn_cur

    # ACL flags an IP as abuse if it sends more than 100 HTTP requests within 10 seconds, which is considered a potential DoS (Denial of Service) attack
    acl abuse src_http_req_rate(https_front) gt 100

    # ACL flags an IP if it has more than 10 concurrent connections, which might indicate an abuse of resources or a bot attempting to flood the server with connections.
    acl too_many_conns src_conn_cur gt 10

    # If the abuse ACL condition is met, the incoming HTTP request will be denied, effectively blocking further traffic from that IP.
    http-request deny if abuse

    # If the too_many_conns ACL condition is met, the TCP connection will be rejected, preventing the client from opening additional connections.
    tcp-request content reject if too_many_conns
    http-request track-sc0 src
    http-request deny deny_status 429 if { sc_http_req_rate(0) gt 20 }



    # Security Headers (OWASP)
    # To Disable iFrame embedding
    http-response set-header X-Frame-Options "DENY"

    # Useful for security because an attacker could upload a file with an incorrect file type (like a .jpg file with malicious JavaScript code inside)
    http-response set-header X-Content-Type-Options "nosniff"

    # It tells browsers that your site should only be accessed over HTTPS, and never HTTP (insecure)
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains"

    # Your site will not send any referrer information when a user clicks on a link to navigate to another site
    http-response set-header Referrer-Policy "no-referrer"

    # Helps prevent cross-site scripting (XSS) and other code injection attacks
    http-response set-header Content-Security-Policy "default-src 'self'; script-src 'self';"

    # This header enables a built-in XSS (cross-site scripting) filter in the browser.
    http-response set-header X-XSS-Protection "1; mode=block"



    # CORS

    # ACL flags requests that use the OPTIONS method, which are typically preflight CORS requests.
    acl is_preflight_options method OPTIONS

    # Log the Origin header
    http-request capture req.hdr(Origin) len 20

    # CORS to only allow request from example.com & example.org
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
--
-- Cross-origin Request Sharing (CORS) implementation for HAProxy Lua host
--
-- CORS RFC:
-- https://www.w3.org/TR/cors/
--
-- Copyright (c) 2019. Nick Ramirez <nramirez@haproxy.com>
-- Copyright (c) 2019. HAProxy Technologies, LLC.

local M={}

-- Loops through array to find the given string.
-- items: array of strings
-- test_str: string to search for
function contains(items, test_str)
  for _,item in pairs(items) do
    if item == test_str then
      return true
    end
  end

  return false
end

M.wildcard_origin_allowed = function(allowed_origins)
  if contains(allowed_origins, "*") then
    return "*"
  end
  return nil
end

M.specifies_scheme = function(s)
  return string.find(s, "^%a+://") ~= nil
end

M.specifies_generic_scheme = function(s)
  return string.find(s, "^//") ~= nil
end

M.begins_with_dot = function(s)
  return string.find(s, "^%.") ~= nil
end

M.trim = function(s)
  return s:gsub("%s+", "")
end

M.build_pattern = function(pattern)
  -- remove spaces
  pattern = M.trim(pattern)

  if pattern ~= nil and pattern ~= '' then
    -- if there is no scheme and the pattern does not begin with a dot, 
    -- add the generic scheme to the beginning of the pattern
    if M.specifies_scheme(pattern) == false and M.specifies_generic_scheme(pattern) == false and M.begins_with_dot(pattern) == false then
      pattern = "//" .. pattern
    end

    -- escape dots and dashes in pattern
    pattern = pattern:gsub("([%.%-])", "%%%1")

    -- an asterisk for the port means allow all ports
    if string.find(pattern, "[:]+%*$") ~= nil then
      pattern = pattern:gsub("[:]+%*$", "[:]+[0-9]+")
    end

    -- append end character
    pattern = pattern .. "$"
    return pattern
  end

  return nil
end

-- If the given origin is found within the allowed_origins string, it is returned. Otherwise, nil is returned.
-- origin: The value from the 'origin' request header
-- allowed_origins: Comma-delimited list of allowed origins. (e.g. localhost,https://localhost:8080,//test.com)
--   e.g. localhost                : allow http(s)://localhost
--   e.g. //localhost              : allow http(s)://localhost
--   e.g. https://mydomain.com     : allow only HTTPS of mydomain.com
--   e.g. http://mydomain.com      : allow only HTTP of mydomain.com
--   e.g. http://mydomain.com:8080 : allow only HTTP of mydomain.com from port 8080
--   e.g. //mydomain.com           : allow only http(s)://mydomain.com
--   e.g. .mydomain.com            : allow ALL subdomains of mydomain.com from ALL source ports
--   e.g. .mydomain.com:443        : allow ALL subdomains of mydomain.com from default HTTPS source port
-- 
--  e.g. ".mydomain.com:443, //mydomain.com:443, //localhost"
--    allows all subdomains and main domain of mydomain.com only for HTTPS from default HTTPS port and allows 
--    all HTTP and HTTPS connections from ALL source port for localhost
--    
M.get_allowed_origin = function(origin, allowed_origins)
  if origin ~= nil then
    -- if wildcard (*) is allowed, return it, which allows all origins
    wildcard_origin = M.wildcard_origin_allowed(allowed_origins)
    if wildcard_origin ~= nil then
      return wildcard_origin
    end

    for index, allowed_origin in ipairs(allowed_origins) do
      pattern = M.build_pattern(allowed_origin)

      if pattern ~= nil then
        if origin:match(pattern) then
          core.Debug("Test: " .. pattern .. ", Origin: " .. origin .. ", Match: yes")
          return origin
        else
          core.Debug("Test: " .. pattern .. ", Origin: " .. origin .. ", Match: no")
        end
      end
    end
  end

  return nil
end

-- Adds headers for CORS preflight request and then attaches them to the response
-- after it comes back from the server. This works with versions of HAProxy prior to 2.2.
-- The downside is that the OPTIONS request must be sent to the backend server first and can't 
-- be intercepted and returned immediately.
-- txn: The current transaction object that gives access to response properties
-- allowed_methods: Comma-delimited list of allowed HTTP methods. (e.g. GET,POST,PUT,DELETE)
-- allowed_headers: Comma-delimited list of allowed headers. (e.g. X-Header1,X-Header2)
function preflight_request_ver1(txn, allowed_methods, allowed_headers)
  core.Debug("CORS: preflight request received")
  txn.http:res_set_header("Access-Control-Allow-Methods", allowed_methods)
  txn.http:res_set_header("Access-Control-Allow-Headers", allowed_headers)
  txn.http:res_set_header("Access-Control-Max-Age", 600)
  core.Debug("CORS: attaching allowed methods to response")
end

-- Add headers for CORS preflight request and then returns a 204 response.
-- The 'reply' function used here is available in HAProxy 2.2+. It allows HAProxy to return
-- a reply without contacting the server.
-- txn: The current transaction object that gives access to response properties
-- origin: The value from the 'origin' request header
-- allowed_methods: Comma-delimited list of allowed HTTP methods. (e.g. GET,POST,PUT,DELETE)
-- allowed_origins: Comma-delimited list of allowed origins. (e.g. localhost,localhost:8080,test.com)
-- allowed_headers: Comma-delimited list of allowed headers. (e.g. X-Header1,X-Header2)
function preflight_request_ver2(txn, origin, allowed_methods, allowed_origins, allowed_headers)
  core.Debug("CORS: preflight request received")

  local reply = txn:reply()
  reply:set_status(204, "No Content")
  reply:add_header("Content-Type", "text/html")
  reply:add_header("Access-Control-Allow-Methods", allowed_methods)
  reply:add_header("Access-Control-Allow-Headers", allowed_headers)
  reply:add_header("Access-Control-Max-Age", 600)

  local allowed_origin = M.get_allowed_origin(origin, allowed_origins)

  if allowed_origin == nil then
    core.Debug("CORS: " .. origin .. " not allowed")
  else
    core.Debug("CORS: " .. origin .. " allowed")
    reply:add_header("Access-Control-Allow-Origin", allowed_origin)

    if allowed_origin ~= "*" then
      reply:add_header("Vary", "Accept-Encoding,Origin")
    end
  end

  core.Debug("CORS: Returning reply to preflight request")
  txn:done(reply)
end

-- When invoked during a request, captures the origin header if present and stores it in a private variable.
-- If the request is OPTIONS and it is a supported version of HAProxy, returns a preflight request reply.
-- Otherwise, the preflight request header is added to the response after it has returned from the server.
-- txn: The current transaction object that gives access to response properties
-- allowed_methods: Comma-delimited list of allowed HTTP methods. (e.g. GET,POST,PUT,DELETE)
-- allowed_origins: Comma-delimited list of allowed origins. (e.g. localhost,localhost:8080,test.com)
-- allowed_headers: Comma-delimited list of allowed headers. (e.g. X-Header1,X-Header2)
function cors_request(txn, allowed_methods, allowed_origins, allowed_headers)
  local headers = txn.http:req_get_headers()
  local transaction_data = {}
  local origin = nil
  local allowed_origins = core.tokenize(allowed_origins, ",")
  
  if headers["origin"] ~= nil and headers["origin"][0] ~= nil then
    core.Debug("CORS: Got 'Origin' header: " .. headers["origin"][0])
    origin = headers["origin"][0]
  end

  -- Bail if client did not send an Origin
  -- for example, it may be a regular OPTIONS request that is not a CORS preflight request
  if origin == nil or origin == '' then
    return
  end
  
  transaction_data["origin"] = origin
  transaction_data["allowed_methods"] = allowed_methods
  transaction_data["allowed_origins"] = allowed_origins
  transaction_data["allowed_headers"] = allowed_headers

  txn:set_priv(transaction_data)

  local method = txn.sf:method()
  transaction_data["method"] = method

  if method == "OPTIONS" and txn.reply ~= nil then
    preflight_request_ver2(txn, origin, allowed_methods, allowed_origins, allowed_headers)
  end
end

-- When invoked during a response, sets CORS headers so that the browser can read the response from permitted domains.
-- txn: The current transaction object that gives access to response properties.
function cors_response(txn)
  local transaction_data = txn:get_priv()

  if transaction_data == nil then
    return
  end
  
  local origin = transaction_data["origin"]
  local allowed_origins = transaction_data["allowed_origins"]
  local allowed_methods = transaction_data["allowed_methods"]
  local allowed_headers = transaction_data["allowed_headers"]
  local method = transaction_data["method"]

  -- Bail if client did not send an Origin
  if origin == nil or origin == '' then
    return
  end

  local allowed_origin = M.get_allowed_origin(origin, allowed_origins)

  if allowed_origin == nil then
    core.Debug("CORS: " .. origin .. " not allowed")
  else
    if method == "OPTIONS" and txn.reply == nil then
      preflight_request_ver1(txn, allowed_methods, allowed_headers)
    end
    
    core.Debug("CORS: " .. origin .. " allowed")
    txn.http:res_set_header("Access-Control-Allow-Origin", allowed_origin)

    if allowed_origin ~= "*" then
      txn.http:res_add_header("Vary", "Accept-Encoding,Origin")
    end
  end
end

-- Register the actions with HAProxy
core.register_action("cors", {"http-req"}, cors_request, 3)
core.register_action("cors", {"http-res"}, cors_response, 0)

return M
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
sudo systemctl start haproxy
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
