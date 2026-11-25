#!/usr/bin/env bash
set -u

echo "=== 1. DNS & Public Domain (spectre-pro.duckdns.org) ==="
getent ahosts spectre-pro.duckdns.org | head -n 2 || true
curl -sS -m 6 -w "HTTPS %{http_code} (%{time_total}s)\n" https://spectre-pro.duckdns.org/openapi.json -o /dev/null || echo "Public domain check failed"

echo "=== 2. SPECTRE Backend (127.0.0.1:8080) ==="
curl -sS -m 5 -w "HTTP %{http_code} (%{time_total}s)\n" http://127.0.0.1:8080/openapi.json -o /dev/null || echo "Backend check failed"

echo "=== 3. ADB / Redroid & MobSF (127.0.0.1:8000) ==="
adb devices 2>&1 || true
curl -sS -m 5 -w "MobSF HTTP %{http_code} (%{time_total}s)\n" http://127.0.0.1:8000/ -o /dev/null || echo "MobSF check failed"

echo "=== 4. Docker Containers ==="
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

echo "=== 5. Memory & Disk ==="
free -h | awk 'NR==1 || NR==2 {print}'
df -h / | awk 'NR==1 || NR==2 {print}'