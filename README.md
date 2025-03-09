# GaleProxy

GaleProxy is a high-performance HTTP proxy server written in Go. It supports multi-port listening, username/password authentication with bcrypt, optional TLS encryption, IPv4/IPv6 dual-stack, and DNS leak prevention. This project is Dockerized for easy deployment and includes an in-container service manager.

## Features
- Multi-port listening via YAML config
- Secure authentication with bcrypt
- Optional TLS encryption
- IPv4/IPv6 support with IPv4 preference
- DNS leak prevention with custom DNS servers
- Connection limiting and timeout configuration
- In-container service management (start, stop, restart, logs)

## Prerequisites
- **Docker**: Install Docker Desktop (Windows/Mac) or Docker Engine (Linux).
- **Go**: Optional, for local development (install from [golang.org/dl/](https://golang.org/dl/)).



## Setup and Running

### 1. Clone the Repository
```
bash
git clone https://github.com/YOUR_USERNAME/galeproxy.git
cd galeproxy
```

### 2. Configure config.yaml

Edit config.yaml with your settings. Example:
```
listeners:
  - ip: "127.0.0.1"
    port: "8080"
users:
  - username: "user1"
    password: "$2a$10$YOUR_BCRYPT_HASH_HERE"
tls_enabled: false
tls_cert_file: "server.crt"
tls_key_file: "server.key"
dns_servers:
  - "1.1.1.1:53"
  - "8.8.8.8:53"
max_connections: 1000
timeout: 30
```

For generating bcrypt password you can use generator websites or using python packages on linux.


3. Build and Run with Docker Compose
```
docker-compose up --build
```

Output:
```
Starting GaleProxy...
GaleProxy started successfully with PID <number>
```

4. Manage the Service Inside the Container

Open a shell in the running container:
```
docker exec -it galeproxy /bin/sh
```

Inside the container, use these commands:

    Start: /root/entrypoint.sh start

```
Starting GaleProxy...
GaleProxy started successfully with PID 123
```

    Stop: /root/entrypoint.sh stop

```
Stopping GaleProxy (PID: 123)...
GaleProxy stopped
```

    Restart: /root/entrypoint.sh restart

```
Stopping GaleProxy (PID: 123)...
GaleProxy stopped
Starting GaleProxy...
GaleProxy started successfully with PID 456
```

    Logs: /root/entrypoint.sh logs
```
2025/03/09 12:00:00 GaleProxy: Starting proxy server 0 on 127.0.0.1:8080 (TLS: false)
```

5. Test the Proxy

From your host:

```
curl --proxy http://user1:yourpassword@127.0.0.1:8080 http://example.com
```

6. Stop the Container

```
docker-compose down
```
