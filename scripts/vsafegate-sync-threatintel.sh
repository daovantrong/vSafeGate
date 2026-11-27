#!/usr/bin/env bash
set -e
TMP_LIST=$(mktemp /tmp/vsafegate_ti_raw.XXXXXX)
IPSET_SCRIPT=$(mktemp /tmp/vsafegate_ti_restore.XXXXXX)
trap 'rm -f "$TMP_LIST" "$IPSET_SCRIPT"' EXIT

curl -fsSL --max-time 15 "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset" >> "$TMP_LIST" 2>/dev/null || true
curl -fsSL --max-time 15 "https://www.spamhaus.org/drop/drop.txt" >> "$TMP_LIST" 2>/dev/null || true

if [ ! -s "$TMP_LIST" ]; then
    exit 0
fi

ipset create vsafegate-threatintel hash:net maxelem 131072 -exist
ipset create vsafegate-threatintel-tmp hash:net maxelem 131072 -exist
ipset flush vsafegate-threatintel-tmp

echo "flush vsafegate-threatintel-tmp" > "$IPSET_SCRIPT"
grep -Eo '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' "$TMP_LIST" | \
    grep -Ev '/0$' | \
    grep -Ev '^(0\.|10\.|127\.|169\.254\.|192\.168\.|100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|224\.|240\.)' | \
    sort -u | awk '{print "add vsafegate-threatintel-tmp " $1 " -exist"}' >> "$IPSET_SCRIPT"

ipset restore < "$IPSET_SCRIPT"
ipset swap vsafegate-threatintel-tmp vsafegate-threatintel
ipset destroy vsafegate-threatintel-tmp
