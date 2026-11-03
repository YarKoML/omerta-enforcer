#!/bin/bash
# vpn-blocklist.sh — пересборка блокировки: цепочка на хосте + блок-лист и
# карантин внутри netns контейнера Amnezia.
# Запускается systemd-таймером (vpn-blocklist.timer) каждые 5 минут.
set -euo pipefail

# === Раскладка сервера: /etc/omerta-enforcer.env ===
ENV_FILE="/etc/omerta-enforcer.env"
if [ ! -f "$ENV_FILE" ]; then
  echo "ОШИБКА: нет $ENV_FILE — заполни раскладку (см. README, «Шаг 4»)"; exit 1
fi
. "$ENV_FILE"
: "${CTR:?нет CTR в $ENV_FILE}"
: "${VPN_SUBNET:?нет VPN_SUBNET в $ENV_FILE}"
: "${AWG_IF:?нет AWG_IF в $ENV_FILE}"
# =====================================================

LIST="/etc/vpn-blocklist.domains"
IPS="/etc/vpn-blocklist.ips"
QCONF="/etc/vpn-quarantine.conf"
CHAIN="VPN-BLK"

# --- параметры карантина (дефолты, если конфига нет) ---
HITCOUNT=5; WINDOW=60; BANTIME=180
if [ -f "$QCONF" ]; then . "$QCONF"; fi

# --- собираем пул IP (домены резолвим через внешний DNS + статика) ---
POOL=$(mktemp)
trap 'rm -f "$POOL"' EXIT
while read -r domain; do
  [ -z "$domain" ] && continue
  dig +short A "$domain" @1.1.1.1 | grep -E '^[0-9.]+$' >> "$POOL" || true
done < "$LIST"
if [ -f "$IPS" ]; then
  grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$' "$IPS" >> "$POOL" || true
fi

# --- ХОСТ: цепочка VPN-BLK в DOCKER-USER ---
iptables -N "$CHAIN" 2>/dev/null || true
iptables -C DOCKER-USER -j "$CHAIN" 2>/dev/null || iptables -I DOCKER-USER 1 -j "$CHAIN"
iptables -F "$CHAIN"
sort -u "$POOL" | while read -r ip; do
  iptables -A "$CHAIN" -s "$VPN_SUBNET" -d "$ip" -j DROP
done

# --- КОНТЕЙНЕР: блок-лист + карантин ---
if [ "$(docker inspect -f '{{.State.Running}}' "$CTR" 2>/dev/null || echo false)" = "true" ]; then
  {
    echo 'iptables -N VPN-BLK-C 2>/dev/null || true'
    echo 'iptables -N BLKHIT 2>/dev/null || true'
    echo 'iptables -N VPNQ 2>/dev/null || true'
    echo 'iptables -N VPN-QCHECK 2>/dev/null || true'
    echo 'iptables -F VPN-BLK-C; iptables -F BLKHIT; iptables -F VPNQ; iptables -F VPN-QCHECK'
    # фиксируем попадание, дропаем пакет
    echo 'iptables -A BLKHIT -m recent --set --name blkh'
    echo "iptables -A BLKHIT -m recent --rcheck --seconds $WINDOW --hitcount $HITCOUNT --name blkh -j VPNQ"
    echo 'iptables -A BLKHIT -j DROP'
    # превышен порог → источник в карантин
    echo 'iptables -A VPNQ -m recent --set --name vpnq -j DROP'
    # проверка карантина: помечен за последние BANTIME сек → DROP всего трафика
    echo "iptables -A VPN-QCHECK -m recent --rcheck --seconds $BANTIME --name vpnq -j DROP"
    # стабильные прыжки (не зависят от параметров — не плодят дублей при смене конфига)
    echo "iptables -C FORWARD -i $AWG_IF -j VPN-QCHECK 2>/dev/null || iptables -I FORWARD 1 -i $AWG_IF -j VPN-QCHECK"
    echo "iptables -C FORWARD -i $AWG_IF -j VPN-BLK-C 2>/dev/null || iptables -I FORWARD 2 -i $AWG_IF -j VPN-BLK-C"
    # IP блок-листа
    sort -u "$POOL" | while read -r ip; do
      echo "iptables -A VPN-BLK-C -d $ip -j BLKHIT"
    done
  } | docker exec -i "$CTR" sh -s
fi