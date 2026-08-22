#!/usr/bin/env bash

set -u

TARGET_HOST="${1:-node1}"
LOG_DIR="../evidence/functional-validation"
TIMESTAMP="$(date +%F-%H%M)"
LOG_FILE="${LOG_DIR}/functional-validation-${TIMESTAMP}.log"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
ANSIBLE_DIR="$REPO_DIR/ansible"

cd "$ANSIBLE_DIR" || exit 1
mkdir -p "$LOG_DIR"

exec > >(tee -a "$LOG_FILE") 2>&1

echo "============================================================"
echo "Streetrack Ubuntu 24.04 Functional Validation"
echo "============================================================"
echo "Target: $TARGET_HOST"
echo "Date:   $(date)"
echo

pass() {
    echo "[PASS] $1"
}

fail() {
    echo "[FAIL] $1"
}

echo "[TEST] Ansible connectivity"
if ansible "$TARGET_HOST" -m ping; then
    pass "Ansible connectivity"
else
    fail "Ansible connectivity"
fi

echo
echo "[TEST] Privilege escalation"
if ansible "$TARGET_HOST" -b -m command -a "id" | grep -q "uid=0(root)"; then
    pass "Ansible privilege escalation"
else
    fail "Ansible privilege escalation"
fi

echo
echo "[TEST] SSH service"
if ansible "$TARGET_HOST" -b -m command -a "systemctl is-active ssh" | grep -q "active"; then
    pass "SSH service is active"
else
    fail "SSH service is not active"
fi

echo
echo "[TEST] auditd service"
if ansible "$TARGET_HOST" -b -m command -a "systemctl is-active auditd" | grep -q "active"; then
    pass "auditd service is active"
else
    fail "auditd service is not active"
fi

echo
echo "[TEST] Network interface configuration"
if ansible "$TARGET_HOST" -m command -a "ip addr"; then
    pass "Network interfaces accessible"
else
    fail "Unable to retrieve network interfaces"
fi

echo
echo "[TEST] Routing table"
if ansible "$TARGET_HOST" -m command -a "ip route"; then
    pass "Routing table accessible"
else
    fail "Unable to retrieve routing table"
fi

echo
echo "[TEST] External network connectivity"
if ansible "$TARGET_HOST" -m command -a "ping -c 4 8.8.8.8"; then
    pass "External network connectivity"
else
    fail "External network connectivity"
fi

echo
echo "[TEST] UFW firewall status"
if ansible "$TARGET_HOST" -b -m command -a "ufw status verbose"; then
    pass "Firewall status retrieved"
else
    fail "Unable to retrieve firewall status"
fi

echo
echo "============================================================"
echo "Functional validation complete"
echo "Log: $LOG_FILE"
echo "============================================================"
