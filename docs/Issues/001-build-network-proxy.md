# Issue 1: Docker build cannot download packages

**Symptom**

`docker compose build` fails at the `apt-get` step:

```
Could not connect to archive.ubuntu.com:80 ... connection timed out
E: Unable to locate package build-essential
```

**Cause**

The build container cannot reach Ubuntu's package servers (or PyPI) from our
network. The VPN works on the host, but the build container does not use it.
On the first proxy attempt, the build also could not reach the VPN proxy:
`host.docker.internal` points to Docker's bridge (`172.17.0.1`), and the VPN
app (FlClash) only listens on `127.0.0.1`.

**Fix**

The Dockerfile tries a direct download first and retries through
`BUILD_PROXY` only if that fails.

1. Copy `.env.example` to `.env` (git-ignored) and set your VPN's local HTTP
   proxy port:
   ```
   BUILD_PROXY=http://127.0.0.1:7890
   ```
2. In `docker-compose.yml`, under `build:`, use the host network so the build
   can reach `127.0.0.1`:
   ```yaml
   network: host
   ```
   (Alternative: turn on "Allow LAN" in the VPN app and use
   `http://host.docker.internal:7890`.)
3. `docker compose build`

Leave `BUILD_PROXY` empty if your network does not need a proxy.
