#!/bin/bash
# Omerta Enforcer — установщик.
# Идемпотентный: повторный запуск не ломает живые списки, токен и раскладку.
# Спрашивает раскладку Amnezia (или берёт существующий /etc/omerta-enforcer.env).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="/etc/omerta-enforcer.env"
TOKEN_FILE="/etc/blocklist-ui.token"

[ "$(id -u)" = 0 ] || { echo "Запусти от root: sudo bash install.sh"; exit 1; }

echo "== 0/7 Разведка: раскладка твоего сервера =="
if [ -f "$ENV_FILE" ]; then
  . "$ENV_FILE"
  echo "Найден $ENV_FILE — использую его, ничего не спрашиваю."
else
  echo "Как узнать эти значения — README, «Шаг 0»."
  DEF_CTR="my-amnezia"; DEF_BRIDGE_IF="wg-br"; DEF_BRIDGE_IP="172.30.100.1"
  DEF_VPN_SUBNET="172.30.100.0/24"; DEF_AWG_IF="awg0"
  read -rp "Имя контейнера Amnezia [$DEF_CTR]: " v; CTR="${v:-$DEF_CTR}"
  read -rp "Интерфейс моста [$DEF_BRIDGE_IF]: " v; BRIDGE_IF="${v:-$DEF_BRIDGE_IF}"
  read -rp "IP моста [$DEF_BRIDGE_IP]: " v; BRIDGE_IP="${v:-$DEF_BRIDGE_IP}"
  read -rp "Подсеть моста (CIDR) [$DEF_VPN_SUBNET]: " v; VPN_SUBNET="${v:-$DEF_VPN_SUBNET}"
  read -rp "Туннель внутри контейнера [$DEF_AWG_IF]: " v; AWG_IF="${v:-$DEF_AWG_IF}"
fi

cat > "$ENV_FILE" <<EOF
# Omerta Enforcer — раскладка этого сервера
CTR="$CTR"
BRIDGE_IF="$BRIDGE_IF"
BRIDGE_IP="$BRIDGE_IP"
VPN_SUBNET="$VPN_SUBNET"
AWG_IF="$AWG_IF"
EOF
chmod 600 "$ENV_FILE"
echo "Раскладка: контейнер=$CTR, мост=$BRIDGE_IF ($BRIDGE_IP, $VPN_SUBNET), туннель=$AWG_IF"

if [ "$(docker inspect -f '{{.State.Running}}' "$CTR" 2>/dev/null || echo false)" != "true" ]; then
  echo "ВНИМАНИЕ: контейнер $CTR не найден/не запущен."
  echo "Установка продолжится, но правила внутри контейнера появятся после старта Amnezia (таймер дотянет за <=5 мин)."
fi

echo "== 1/7 Пакеты =="
apt update
DEBIAN_FRONTEND=noninteractive apt install -y dnsmasq dnsutils iptables-persistent python3-flask

echo "== 2/7 Скрипты =="
install -m 755 "$REPO_DIR/scripts/vpn-blocklist.sh" /usr/local/sbin/vpn-blocklist.sh
install -m 755 "$REPO_DIR/scripts/vpn-block-add.sh"  /usr/local/sbin/vpn-block-add.sh

echo "== 3/7 Конфиги =="
if [ -f /etc/dnsmasq.d/vpn-blacklist.conf ]; then
  echo "  dnsmasq-конфиг уже существует — не трогаю (твои домены живут в нём)"
else
  install -m 644 "$REPO_DIR/dnsmasq/vpn-blacklist.conf" /etc/dnsmasq.d/vpn-blacklist.conf
  sed -i "s|@@BRIDGE_IP@@|$BRIDGE_IP|" /etc/dnsmasq.d/vpn-blacklist.conf
fi
# списки и карантин: существующие на сервере НЕ затираем
for f in vpn-blocklist.domains vpn-blocklist.ips vpn-quarantine.conf; do
  if [ -f "/etc/$f" ]; then
    echo "  /etc/$f уже существует — не трогаю"
  else
    install -m 644 "$REPO_DIR/config/$f" "/etc/$f"
  fi
done

echo "== 4/7 Токен UI =="
if [ -f "$TOKEN_FILE" ]; then
  echo "  токен уже есть — не трогаю"
else
  openssl rand -hex 16 > "$TOKEN_FILE"
  chmod 600 "$TOKEN_FILE"
  echo "  Твой токен UI: $(cat "$TOKEN_FILE")"
fi

echo "== 5/7 iptables: перехват DNS из VPN =="
# любой DNS-запрос из VPN-подсети заворачивается в наш dnsmasq
iptables -t nat -C PREROUTING -i "$BRIDGE_IF" -s "$VPN_SUBNET" -p udp --dport 53 -j DNAT --to-destination "$BRIDGE_IP:53" 2>/dev/null || \
iptables -t nat -A PREROUTING -i "$BRIDGE_IF" -s "$VPN_SUBNET" -p udp --dport 53 -j DNAT --to-destination "$BRIDGE_IP:53"
iptables -t nat -C PREROUTING -i "$BRIDGE_IF" -s "$VPN_SUBNET" -p tcp --dport 53 -j DNAT --to-destination "$BRIDGE_IP:53" 2>/dev/null || \
iptables -t nat -A PREROUTING -i "$BRIDGE_IF" -s "$VPN_SUBNET" -p tcp --dport 53 -j DNAT --to-destination "$BRIDGE_IP:53"
netfilter-persistent save

echo "== 6/7 systemd + UI =="
mkdir -p /opt/blocklist-ui
install -m 644 "$REPO_DIR/ui/app.py"                       /opt/blocklist-ui/app.py
install -m 644 "$REPO_DIR/systemd/vpn-blocklist.service"  /etc/systemd/system/
install -m 644 "$REPO_DIR/systemd/vpn-blocklist.timer"   /etc/systemd/system/
install -m 644 "$REPO_DIR/systemd/blocklist-ui.service"  /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now vpn-blocklist.timer
systemctl start vpn-blocklist.service
systemctl restart blocklist-ui.service

echo
echo "== 7/7 Проверка =="
systemctl is-active dnsmasq blocklist-ui.service vpn-blocklist.timer
echo "Правил в VPN-BLK: $(iptables -S VPN-BLK | tail -n +2 | wc -l)"
echo
echo "Готово. Подключись к VPN и открой: http://$BRIDGE_IP:8800"
echo "Токен: cat $TOKEN_FILE"