#!/bin/bash
set -e

PKG="allsafe-access"
SRC_DIR=$(pwd)

DEBIAN_DIR="$SRC_DIR/debian"
INSTALL_FILE="$DEBIAN_DIR/$PKG.install"
BINARIES_FILE="$DEBIAN_DIR/source/include-binaries"

mkdir -p "$DEBIAN_DIR/source"

echo "[*] Generating $INSTALL_FILE ..."
> "$INSTALL_FILE"

echo "[*] Generating $BINARIES_FILE ..."
> "$BINARIES_FILE"

# 1. Binaries from bin/ → usr/bin/
for f in bin/*; do
  [ -f "$f" ] || continue
  echo "$f usr/bin/" >> "$INSTALL_FILE"
  echo "$f" >> "$BINARIES_FILE"
done

# 2. Proxy templates → usr/share/allsafe-proxy/templates/
for f in cmd/allsafe-proxy/templates/*; do
  [ -f "$f" ] || continue
  echo "$f usr/share/allsafe-proxy/templates/" >> "$INSTALL_FILE"
  echo "$f" >> "$BINARIES_FILE"
done

# 3. Configs for proxy
for f in configs/configs/allsafeproxy/*; do
  [ -f "$f" ] || continue
  echo "$f etc/allsafe-proxy/" >> "$INSTALL_FILE"
  echo "$f" >> "$BINARIES_FILE"
done

# 4. Configs for agent
for f in configs/configs/allsafeagent/*; do
  [ -f "$f" ] || continue
  echo "$f etc/allsafe-agent/" >> "$INSTALL_FILE"
  echo "$f" >> "$BINARIES_FILE"
done

# 5. Configs for cli
for f in configs/configs/allsafecli/*; do
  [ -f "$f" ] || continue
  echo "$f etc/allsafe-cli/" >> "$INSTALL_FILE"
  echo "$f" >> "$BINARIES_FILE"
done

# 6. Certs for proxy
for f in configs/certs/proxy.*; do
  [ -f "$f" ] || continue
  echo "$f etc/allsafe-proxy/certs/" >> "$INSTALL_FILE"
  echo "$f" >> "$BINARIES_FILE"
done
if [ -f configs/certs/proxy_ca.crt ]; then
  echo "configs/certs/proxy_ca.crt etc/allsafe-proxy/certs/" >> "$INSTALL_FILE"
  echo "configs/certs/proxy_ca.crt" >> "$BINARIES_FILE"
fi

# 7. Certs for agent
for f in configs/certs/agent.*; do
  [ -f "$f" ] || continue
  echo "$f etc/allsafe-agent/certs/" >> "$INSTALL_FILE"
  echo "$f" >> "$BINARIES_FILE"
done
if [ -f configs/certs/agent_ca.crt ]; then
  echo "configs/certs/agent_ca.crt etc/allsafe-agent/certs/" >> "$INSTALL_FILE"
  echo "configs/certs/agent_ca.crt" >> "$BINARIES_FILE"
fi

# 8. Roles
for f in configs/roles/*; do
  [ -f "$f" ] || continue
  echo "$f etc/allsafe-access/role/" >> "$INSTALL_FILE"
  echo "$f" >> "$BINARIES_FILE"
done

echo "[*] Done. Generated:"
echo "  - $INSTALL_FILE"
echo "  - $BINARIES_FILE"
