#!/usr/bin/env python3
"""Omerta Enforcer — Web UI блэклиста VPN.

Слушает на IP моста (из /etc/omerta-enforcer.env) — доступен ТОЛЬКО под VPN.
Вход по токену (файл задаётся install.sh'ом).
Умеет: домены (dnsmasq + IP-блэклист), статические IP/CIDR (IP-блэклист),
массовое удаление галочками, карантин с разбаном и настройками.
"""
import ipaddress
import re
import secrets
import subprocess
from functools import wraps
from pathlib import Path

from flask import Flask, flash, redirect, render_template_string, request, session

DNS_CONF = Path("/etc/dnsmasq.d/vpn-blacklist.conf")
DOMAINS_FILE = Path("/etc/vpn-blocklist.domains")
IPS_FILE = Path("/etc/vpn-blocklist.ips")
QCONF = Path("/etc/vpn-quarantine.conf")
ENV_FILE = Path("/etc/omerta-enforcer.env")
TOKEN_FILE = Path("/etc/blocklist-ui.token")
BIND_PORT = 8800
DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$"
)


def load_env():
    """Раскладка сервера из env-файла (создаётся install.sh или вручную, Шаг 4)."""
    vals = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            m = re.match(r'\s*(CTR|BRIDGE_IF|BRIDGE_IP|VPN_SUBNET|AWG_IF)\s*=\s*"?([^"\s#]+)"?', line)
            if m:
                vals[m.group(1)] = m.group(2)
    return vals


ENV = load_env()
CTR = ENV.get("CTR", "my-amnezia")
BIND_IP = ENV.get("BRIDGE_IP", "172.30.100.1")

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)


def is_ip(s):
    """Проверка, что строка — валидный IP или CIDR."""
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False


def banned_clients():
    """IP клиентов, находящихся в карантине (список vpnq в контейнере)."""
    out = run(["docker", "exec", CTR, "cat", "/proc/net/xt_recent/vpnq"])
    return sorted({m.group(1) for m in re.finditer(r"^src=(\S+)", out, re.M)})


def q_params():
    """Текущие параметры карантина из конфига (с дефолтами)."""
    vals = {"HITCOUNT": "5", "WINDOW": "60", "BANTIME": "180"}
    if QCONF.exists():
        for line in QCONF.read_text().splitlines():
            m = re.match(r"\s*(HITCOUNT|WINDOW|BANTIME)\s*=\s*([0-9]+)", line)
            if m:
                vals[m.group(1)] = m.group(2)
    return vals


def run(cmd):
    """Выполнить команду, вернуть stdout+stderr."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return (r.stdout + r.stderr).strip() or "(нет вывода)"
    except Exception as e:
        return f"ОШИБКА: {e}"


def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not session.get("ok"):
            return redirect("/login")
        return f(*a, **kw)
    return wrapper


STYLE = """
body{font-family:system-ui,sans-serif;background:#101418;color:#e8eaed;max-width:860px;margin:32px auto;padding:0 16px}
h1,h2{font-size:22px}h2{margin-top:28px}
table{width:100%;border-collapse:collapse;margin-top:8px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #2a2f36;font-size:14px}
th{color:#9aa0a6;font-weight:normal}
textarea{width:100%;min-height:90px;background:#1a1f26;color:#e8eaed;border:1px solid #3a4048;border-radius:8px;padding:10px;box-sizing:border-box;font-family:inherit}
button{background:#2563eb;color:#fff;border:0;border-radius:8px;padding:9px 16px;cursor:pointer;font-size:14px}
button.del{background:#7f1d1d;padding:4px 10px}
.msg{background:#1a2a1a;border:1px solid #2f4f2f;border-radius:8px;padding:10px;margin:10px 0;white-space:pre-wrap;font-size:13px}
.bad{color:#f87171}.good{color:#4ade80}
input[type=password]{background:#1a1f26;color:#e8eaed;border:1px solid #3a4048;border-radius:8px;padding:10px;width:280px}
input[type=number]{background:#1a1f26;color:#e8eaed;border:1px solid #3a4048;border-radius:8px;padding:6px;width:100px}
"""

PAGE = """<!doctype html><html lang=ru><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>Omerta Enforcer</title>
<style>""" + STYLE + """</style></head><body>
<h1>🐟 Omerta Enforcer</h1>
{% for m in get_flashed_messages() %}<div class="msg">{{ m }}</div>{% endfor %}
<p>dnsmasq: <b class="{{ 'good' if status.dnsmasq=='active' else 'bad' }}">{{ status.dnsmasq }}</b>
 &middot; таймер: <b class="{{ 'good' if status.timer=='active' else 'bad' }}">{{ status.timer }}</b>
 &middot; правил в VPN-BLK: <b>{{ status.rules }}</b></p>

<h2>Добавить домены / IP / подсети</h2>
<form method=post action=/add>
<textarea name=domains placeholder="по одному в строке — домены, IP или CIDR&#10;dom1.ru&#10;5.61.23.19&#10;45.132.0.0/16"></textarea>
<p><button>Заблокировать</button></p></form>

<form method=post action=/remove-many>
<input type=hidden name=kind value=domain>
<h2>Домены ({{ domains|length }})</h2>
<table><tr><th><input type=checkbox onclick="for(var c of this.closest('table').querySelectorAll('input[name=sel]'))c.checked=this.checked"></th>
<th>Домен</th><th>dig @127.0.0.1</th><th></th></tr>
{% for d in domains %}
<tr><td><input type=checkbox name=sel value="{{ d }}"></td>
<td>{{ d }}</td>
<td class="{{ 'good' if checks[d]=='0.0.0.0' else 'bad' }}">{{ checks[d] }}</td>
<td><button name=entry value="{{ d }}" formaction=/remove class=del>✕</button></td></tr>
{% endfor %}</table>
<p><button>Удалить отмеченные домены</button></p></form>

<form method=post action=/remove-many>
<input type=hidden name=kind value=ip>
<h2>IP-адреса / подсети ({{ ips|length }})</h2>
<table><tr><th><input type=checkbox onclick="for(var c of this.closest('table').querySelectorAll('input[name=sel]'))c.checked=this.checked"></th>
<th>IP / CIDR</th><th>Статус</th><th></th></tr>
{% for i in ips %}
<tr><td><input type=checkbox name=sel value="{{ i }}"></td>
<td>{{ i }}</td>
<td class="{{ 'good' if ip_checks[i]=='DROP ✓' else 'bad' }}">{{ ip_checks[i] }}</td>
<td><button name=entry value="{{ i }}" formaction=/remove class=del>✕</button></td></tr>
{% endfor %}</table>
<p><button>Удалить отмеченные IP</button></p></form>

<h2>Карантин ({{ banned|length }})</h2>
{% if banned %}
<table><tr><th>Клиент</th><th></th></tr>
{% for b in banned %}
<tr><td>{{ b }}</td>
<td><form method=post action=/unban style="display:inline">
<button name=ip value="{{ b }}" class=del>✕ Разбанить</button></form></td></tr>
{% endfor %}</table>
{% else %}<p style="color:#9aa0a6">Пусто — никто не забанен</p>{% endif %}

<h2>Настройки карантина</h2>
<form method=post action=/settings>
<table><tr><th>Параметр</th><th>Значение</th><th>Смысл</th></tr>
<tr><td>Попаданий до бана (1–20)</td>
<td><input type=number name=HITCOUNT value="{{ q.HITCOUNT }}" min=1 max=20></td>
<td>пакетов в блок-лист за окно</td></tr>
<tr><td>Окно подсчёта, сек</td>
<td><input type=number name=WINDOW value="{{ q.WINDOW }}" min=10></td>
<td>за какой срок считаем попадания</td></tr>
<tr><td>Длительность бана, сек</td>
<td><input type=number name=BANTIME value="{{ q.BANTIME }}" min=10></td>
<td>через это время бан снимется сам</td></tr>
</table>
<p><button>Сохранить и применить</button></p></form>
</body></html>"""

LOGIN = """<!doctype html><html lang=ru><head><meta charset=utf-8>
<title>Вход</title><style>""" + STYLE + """</style></head><body>
<h1>🐟 Omerta Enforcer</h1>
<form method=post action=/login>
<p><input type=password name=token placeholder="Токен" autofocus></p>
<p><button>Войти</button></p></form></body></html>"""


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        saved = TOKEN_FILE.read_text().strip()
        if secrets.compare_digest(request.form.get("token", ""), saved):
            session["ok"] = True
            return redirect("/")
        flash("Неверный токен")
    return render_template_string(LOGIN)


@app.route("/")
@login_required
def index():
    domains = [d for d in DOMAINS_FILE.read_text().splitlines() if d.strip()]
    ips = [i for i in (IPS_FILE.read_text().splitlines() if IPS_FILE.exists() else []) if i.strip()]
    status = {
        "dnsmasq": run(["systemctl", "is-active", "dnsmasq"]),
        "timer": run(["systemctl", "is-active", "vpn-blocklist.timer"]),
        "rules": run(["bash", "-c", "iptables -S VPN-BLK | tail -n +2 | wc -l"]),
    }
    checks = {d: run(["bash", "-c", f"dig +short A {d} @127.0.0.1 | paste -sd' '"]) for d in domains}
    ip_checks = {}
    rules = run(["iptables", "-S", "VPN-BLK"])
    for i in ips:
        needle = i if "/" in i else i + "/32"
        ip_checks[i] = "DROP ✓" if f" -d {needle} " in rules else "НЕТ В ЦЕПОЧКЕ"
    return render_template_string(PAGE, domains=domains, checks=checks,
                                  ips=ips, ip_checks=ip_checks, status=status,
                                  banned=banned_clients(), q=q_params())


@app.route("/add", methods=["POST"])
@login_required
def add():
    raw = request.form.get("domains", "").replace(",", "\n")
    entries = [e.strip() for e in raw.split() if e.strip()]
    valid = [e for e in entries if DOMAIN_RE.match(e) or is_ip(e)]
    invalid = [e for e in entries if not (DOMAIN_RE.match(e) or is_ip(e))]
    if not valid:
        flash("Ни одного валидного домена/IP" + (f"; отклонены: {', '.join(invalid)}" if invalid else ""))
        return redirect("/")
    out = run(["/usr/local/sbin/vpn-block-add.sh", *valid])
    flash("Добавлены: " + ", ".join(valid) + "\n" + out)
    return redirect("/")


@app.route("/remove", methods=["POST"])
@login_required
def remove():
    entry = request.form.get("entry", "").strip()
    kind = request.form.get("kind", "domain")

    if kind == "ip":
        if not is_ip(entry):
            flash(f"Некорректный IP: {entry}")
            return redirect("/")
        IPS_FILE.write_text("\n".join(
            l for l in IPS_FILE.read_text().splitlines() if l.strip() and l.strip() != entry
        ) + "\n")
        run(["systemctl", "start", "vpn-blocklist.service"])
        flash(f"IP удалён: {entry}")
        return redirect("/")

    if not DOMAIN_RE.match(entry):
        flash(f"Некорректный домен: {entry}")
        return redirect("/")
    lines = DNS_CONF.read_text().splitlines()
    DNS_CONF.write_text("\n".join(
        l for l in lines if l not in (f"address=/{entry}/0.0.0.0", f"address=/{entry}/::")
    ) + "\n")
    DOMAINS_FILE.write_text("\n".join(
        l for l in DOMAINS_FILE.read_text().splitlines() if l.strip() and l.strip() != entry
    ) + "\n")
    test = subprocess.run(["dnsmasq", "--test"], capture_output=True, text=True)
    if test.returncode != 0:
        flash("КОНФИГ СЛОМАН, рестарт отменён!\n" + (test.stdout + test.stderr))
        return redirect("/")
    run(["systemctl", "restart", "dnsmasq"])
    run(["systemctl", "start", "vpn-blocklist.service"])
    flash(f"Удалён: {entry}")
    return redirect("/")


@app.route("/remove-many", methods=["POST"])
@login_required
def remove_many():
    kind = request.form.get("kind", "domain")
    selected = request.form.getlist("sel")
    if not selected:
        flash("Ничего не отмечено")
        return redirect("/")

    if kind == "ip":
        bad = [e for e in selected if not is_ip(e)]
        good = [e for e in selected if is_ip(e)]
        if good:
            keep = {l.strip() for l in IPS_FILE.read_text().splitlines() if l.strip()} - set(good)
            IPS_FILE.write_text("\n".join(sorted(keep)) + "\n")
            run(["systemctl", "start", "vpn-blocklist.service"])
        flash(f"Удалено IP: {len(good)}" + (f"; пропущены: {', '.join(bad)}" if bad else ""))
        return redirect("/")

    bad = [e for e in selected if not DOMAIN_RE.match(e)]
    good = [e for e in selected if DOMAIN_RE.match(e)]
    if good:
        conf = DNS_CONF.read_text().splitlines()
        for e in good:
            conf = [l for l in conf if l not in (f"address=/{e}/0.0.0.0", f"address=/{e}/::")]
        DNS_CONF.write_text("\n".join(conf) + "\n")
        gone = set(good)
        DOMAINS_FILE.write_text("\n".join(
            l for l in DOMAINS_FILE.read_text().splitlines() if l.strip() and l.strip() not in gone
        ) + "\n")
        test = subprocess.run(["dnsmasq", "--test"], capture_output=True, text=True)
        if test.returncode != 0:
            flash("КОНФИГ СЛОМАН, рестарт отменён!\n" + (test.stdout + test.stderr))
            return redirect("/")
        run(["systemctl", "restart", "dnsmasq"])
        run(["systemctl", "start", "vpn-blocklist.service"])
    flash(f"Удалено доменов: {len(good)}" + (f"; пропущены: {', '.join(bad)}" if bad else ""))
    return redirect("/")


@app.route("/unban", methods=["POST"])
@login_required
def unban():
    ip = request.form.get("ip", "").strip()
    if not is_ip(ip):
        flash(f"Некорректный IP: {ip}")
        return redirect("/")
    out = run(["docker", "exec", CTR, "sh", "-c",
               f"echo -{ip} > /proc/net/xt_recent/vpnq; echo -{ip} > /proc/net/xt_recent/blkh"])
    if "ОШИБКА" in out:
        flash(f"Ошибка разбана {ip}:\n{out}")
    else:
        flash(f"Разбанен: {ip}")
    return redirect("/")


@app.route("/settings", methods=["POST"])
@login_required
def settings():
    vals = {}
    for key in ("HITCOUNT", "WINDOW", "BANTIME"):
        raw = request.form.get(key, "").strip()
        if not raw.isdigit():
            flash(f"{key} должно быть числом")
            return redirect("/")
        vals[key] = int(raw)
    if not (1 <= vals["HITCOUNT"] <= 20):
        flash("HITCOUNT — от 1 до 20 (лимит xt_recent на источник)")
        return redirect("/")
    if vals["WINDOW"] < 10 or vals["BANTIME"] < 10:
        flash("WINDOW и BANTIME — минимум 10 секунд")
        return redirect("/")
    QCONF.write_text(
        "# Параметры карантина VPN-клиентов\n"
        f"HITCOUNT={vals['HITCOUNT']}\n"
        f"WINDOW={vals['WINDOW']}\n"
        f"BANTIME={vals['BANTIME']}\n"
    )
    out = run(["systemctl", "start", "vpn-blocklist.service"])
    if "ОШИБКА" in out:
        flash(f"Настройки сохранены, но применение упало:\n{out}")
    else:
        flash(f"Сохранено и применено: попаданий={vals['HITCOUNT']}, "
              f"окно={vals['WINDOW']}с, бан={vals['BANTIME']}с")
    return redirect("/")


if __name__ == "__main__":
    app.run(host=BIND_IP, port=BIND_PORT)