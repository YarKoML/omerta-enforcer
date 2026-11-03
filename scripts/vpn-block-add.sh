#!/bin/bash
# vpn-block-add.sh — добавить домены и/или IP/CIDR в блэклист VPN.
# Идемпотентный: повторный запуск не плодит дубли.
# Пример: sudo vpn-block-add.sh userapi.com 5.61.23.19 45.132.0.0/16
set -euo pipefail

DNS_CONF="/etc/dnsmasq.d/vpn-blacklist.conf"
DOMAINS="/etc/vpn-blocklist.domains"
IPS="/etc/vpn-blocklist.ips"

[ $# -eq 0 ] && { echo "Использование: $0 <домен|ip|cidr> [...]"; exit 1; }
[ -f "$IPS" ] || touch "$IPS"

DM_RE='^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$'
valid_ip() { python3 -c "import ipaddress,sys; ipaddress.ip_network(sys.argv[1], strict=False)" "$1" >/dev/null 2>&1; }

new_domains=()
new_ips=()

for entry in "$@"; do
  if valid_ip "$entry"; then
    if grep -qxF "$entry" "$IPS"; then
      echo "IP:   $entry — уже есть"
    else
      echo "$entry" >> "$IPS"
      new_ips+=("$entry")
      echo "IP:   $entry — добавлен"
    fi
  elif [[ "$entry" =~ $DM_RE ]]; then
    if grep -qE "^address=/$entry/" "$DNS_CONF"; then
      echo "DNS:  $entry — уже есть"
    else
      printf 'address=/%s/0.0.0.0\naddress=/%s/::\n' "$entry" "$entry" >> "$DNS_CONF"
      new_domains+=("$entry")
      echo "DNS:  $entry — добавлен"
    fi
    if grep -qxF "$entry" "$DOMAINS"; then
      echo "LIST: $entry — уже есть"
    else
      echo "$entry" >> "$DOMAINS"
      echo "LIST: $entry — добавлен"
    fi
  else
    echo "ПРОПУСК: '$entry' — ни домен, ни IP"
  fi
done

# dnsmasq трогаем только если были домены; проверка ДО рестарта —
# сломанный конфиг = у всех клиентов мёртвый DNS
if [ ${#new_domains[@]} -gt 0 ]; then
  if ! dnsmasq --test >/dev/null 2>&1; then
    echo "ОШИБКА: конфиг dnsmasq невалиден, рестарт отменён!"; dnsmasq --test; exit 1
  fi
  systemctl restart dnsmasq
fi
systemctl start vpn-blocklist.service

echo
echo "=== Проверка ==="
for d in "${new_domains[@]}"; do
  printf '%-25s -> %s\n' "$d" "$(dig +short A "$d" @127.0.0.1 | paste -sd' ')"
done
for ip in "${new_ips[@]}"; do
  needle="$ip"; [[ "$needle" != */* ]] && needle="$needle/32"
  if iptables -S VPN-BLK | grep -q -- " -d $needle "; then
    printf '%-25s -> DROP в VPN-BLK\n' "$ip"
  else
    printf '%-25s -> НЕ НАЙДЕН в VPN-BLK!\n' "$ip"
  fi
done