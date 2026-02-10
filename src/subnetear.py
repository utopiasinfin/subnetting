#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
subnetear.py – IPv4-Subnetting-Helper (LPIC / IHK / CompTIA Style)

Ziel:
- In der Praxis schnell Subnetze berechnen (Network/Broadcast/Hosts/Maske/Wildcard)
- Didaktisch: Borrowed Bits, Host Bits, Magic Number, interessantes Oktett
- Menü + saubere Eingabeprüfung
- Export: Markdown + CSV (für Doku / Berichtsheft)

MODI (Menü):
  1) Netzwerk in N Subnetze aufteilen
  2) Netzwerk auf Ziel-Präfix /xx aufteilen
  3) Netzwerk so teilen, dass X nutzbare Hosts/Subnetz möglich sind
  4) IP prüfen: In welches Subnetz fällt eine IP? (innerhalb eines Ausgangsnetzes)
  5) Ein Subnetz analysieren (Netz/Broadcast/Hosts/Maske/Wildcard)

Hinweis (Real Life):
- /31 und /32 haben keine "klassischen" Hostbereiche. Das behandeln wir korrekt.
"""

from __future__ import annotations

import csv
import ipaddress
import math
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


# ============================================================
# 1) "Ferrari"-Ausgabe: Farben + Layout (abschaltbar)
# ============================================================

class UI:
    def __init__(self, use_color: bool = True) -> None:
        self.use_color = use_color and sys.stdout.isatty()

    def c(self, text: str, code: str) -> str:
        if not self.use_color:
            return text
        return f"\033[{code}m{text}\033[0m"

    @property
    def H(self) -> str:  # Headline
        return "1;36"    # bold cyan

    @property
    def OK(self) -> str:
        return "1;32"    # bold green

    @property
    def WRN(self) -> str:
        return "1;33"    # bold yellow

    @property
    def ERR(self) -> str:
        return "1;31"    # bold red

    @property
    def DIM(self) -> str:
        return "2"       # dim

    def headline(self, text: str) -> None:
        print(self.c(f"\n{text}", self.H))
        print(self.c("─" * max(20, len(text)), self.DIM))

    def info(self, text: str) -> None:
        print(text)

    def success(self, text: str) -> None:
        print(self.c(text, self.OK))

    def warn(self, text: str) -> None:
        print(self.c(text, self.WRN))

    def error(self, text: str) -> None:
        print(self.c(text, self.ERR))


# ============================================================
# 2) Datenstruktur für Ausgabe/Export
# ============================================================

@dataclass(frozen=True)
class SubnetInfo:
    subnet: str
    netmask: str
    wildcard: str
    network: str
    broadcast: str
    first_host: str
    last_host: str
    usable_hosts: int
    magic_number: int
    interesting_octet: int
    mask_octet_value: int


# ============================================================
# 3) Hilfsfunktionen (Subnetting-Grundlagen)
# ============================================================

def mask_from_prefix(prefix: int) -> str:
    """Wandelt /27 -> 255.255.255.224"""
    return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)

def wildcard_from_mask(mask: str) -> str:
    """Inverse Maske (Wildcard): 255.255.255.0 -> 0.0.0.255"""
    return ".".join(str(255 - int(o)) for o in mask.split("."))

def block_size(prefix: int) -> int:
    """Anzahl ADRESSEN pro Subnetz (inkl. Netz + Broadcast, falls vorhanden)"""
    return 2 ** (32 - prefix)

def interesting_octet(prefix: int) -> tuple[int, int, int]:
    """
    Liefert Magic Number + interessantes Oktett (1-basiert) + Maskenwert im interessanten Oktett.

    Beispiel /26:
      Maske: 255.255.255.192 -> interessantes Oktett: 4, Maskenwert: 192 -> Magic: 256 - 192 = 64
    """
    netmask = ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask
    octets = list(map(int, str(netmask).split(".")))

    # Wenn Prefix genau auf Oktettgrenze liegt: Magic ist 1 (formal), Maskenwert 255.
    # Für didaktische Ausgabe ist Magic=1 in diesem Fall "irrelevant", aber wir geben es konsistent zurück.
    if prefix % 8 == 0:
        return 1, prefix // 8, 255

    idx = prefix // 8  # 0-basiert
    mask_oct = octets[idx]
    magic = 256 - mask_oct
    return magic, idx + 1, mask_oct

def describe_subnet(net: ipaddress.IPv4Network) -> SubnetInfo:
    """
    Erzeugt alle wichtigen Infos für 1 Subnetz.
    Regeln:
    - /0..../30: klassisch: usable = total - 2, first=+1, last=-1
    - /31: RFC 3021 point-to-point: 2 Adressen, keine Broadcast/Netz-Trennung im klassischen Sinn
    - /32: genau 1 Adresse
    """
    total = net.num_addresses
    netmask = str(net.netmask)
    wildcard = wildcard_from_mask(netmask)

    magic, oct_no, mask_oct = interesting_octet(net.prefixlen)

    if net.prefixlen <= 30:
        usable = total - 2
        first = str(net.network_address + 1)
        last = str(net.broadcast_address - 1)
    elif net.prefixlen == 31:
        # /31: 2 Adressen, "usable" = 2 (P2P), first/last = beide Adressen
        usable = 2
        first = str(net.network_address)
        last = str(net.broadcast_address)
    else:  # /32
        usable = 1
        first = str(net.network_address)
        last = str(net.network_address)

    return SubnetInfo(
        subnet=str(net),
        netmask=netmask,
        wildcard=wildcard,
        network=str(net.network_address),
        broadcast=str(net.broadcast_address),
        first_host=first,
        last_host=last,
        usable_hosts=usable,
        magic_number=magic,
        interesting_octet=oct_no,
        mask_octet_value=mask_oct,
    )


# ============================================================
# 4) Subnetting-Logik (N / Prefix / Hosts)
# ============================================================

def subnet_by_count(net: ipaddress.IPv4Network, n: int) -> tuple[int, list[ipaddress.IPv4Network], int]:
    """
    Netzwerk in N Subnetze aufteilen:
      borrowed_bits = ceil(log2(n))
      new_prefix = old_prefix + borrowed_bits
    """
    borrowed_bits = math.ceil(math.log2(n))
    new_prefix = net.prefixlen + borrowed_bits

    if new_prefix > 32:
        raise ValueError("Zu viele Subnetze: Präfix würde > /32 werden.")

    subs = list(net.subnets(new_prefix=new_prefix))
    return new_prefix, subs, borrowed_bits

def subnet_by_hosts(net: ipaddress.IPv4Network, hosts: int) -> tuple[int, list[ipaddress.IPv4Network], int]:
    """
    Netzwerk so teilen, dass mindestens 'hosts' nutzbare Hosts pro Subnetz möglich sind.

    Rechenlogik:
      Hosts brauchen +2 (Netz + Broadcast) -> außer Spezialfälle /31,/32
      host_bits = ceil(log2(hosts + 2))
      new_prefix = 32 - host_bits
    """
    if hosts <= 0:
        raise ValueError("Hosts müssen >= 1 sein.")

    host_bits = math.ceil(math.log2(hosts + 2))
    new_prefix = 32 - host_bits

    if new_prefix < net.prefixlen:
        raise ValueError("Nicht möglich: gewünschte Hostanzahl passt nicht in das Ausgangsnetz.")

    subs = list(net.subnets(new_prefix=new_prefix))
    return new_prefix, subs, host_bits


# ============================================================
# 5) Eingaben (robust, IHK-Style)
# ============================================================

def ask_int(ui: UI, prompt: str, min_v: int = 1, max_v: int | None = None) -> int:
    while True:
        raw = input(prompt).strip()
        try:
            v = int(raw)
            if v < min_v:
                ui.error(f"Ungültig: Zahl muss >= {min_v} sein.")
                continue
            if max_v is not None and v > max_v:
                ui.error(f"Ungültig: Zahl muss <= {max_v} sein.")
                continue
            return v
        except ValueError:
            ui.error("Ungültige Zahl. Beispiel: 8")

def ask_net(ui: UI, prompt: str) -> ipaddress.IPv4Network:
    while True:
        raw = input(prompt).strip()
        try:
            net = ipaddress.ip_network(raw, strict=False)
            if not isinstance(net, ipaddress.IPv4Network):
                ui.error("Bitte nur IPv4 (z.B. 192.168.1.0/24).")
                continue
            return net
        except ValueError:
            ui.error("Ungültiges Format. Beispiel: 192.168.1.0/24")

def ask_ip(ui: UI, prompt: str) -> ipaddress.IPv4Address:
    while True:
        raw = input(prompt).strip()
        try:
            ip = ipaddress.ip_address(raw)
            if not isinstance(ip, ipaddress.IPv4Address):
                ui.error("Bitte nur IPv4 (z.B. 192.168.1.10).")
                continue
            return ip
        except ValueError:
            ui.error("Ungültige IPv4-Adresse. Beispiel: 10.0.0.5")

def yes_no(prompt: str) -> bool:
    return input(prompt).strip().lower().startswith(("j", "y", "s"))


# ============================================================
# 6) Ausgabe + Export
# ============================================================

def print_summary(ui: UI, base: ipaddress.IPv4Network, new_prefix: int) -> None:
    ui.info(f"Ausgangsnetz : {base}")
    ui.info(f"Neue Maske   : {mask_from_prefix(new_prefix)}  (/{new_prefix})")
    m = mask_from_prefix(new_prefix)
    ui.info(f"Wildcard     : {wildcard_from_mask(m)}")
    ui.info(f"Blockgröße   : {block_size(new_prefix)} Adressen pro Subnetz")

    magic, oct_no, mask_oct = interesting_octet(new_prefix)
    ui.info(f"Magic Number : {magic} (im {oct_no}. Oktett, Maskenwert {mask_oct})")

def print_subnets(ui: UI, infos: list[SubnetInfo], limit: int | None = None) -> None:
    show = infos if limit is None else infos[:limit]
    for i, info in enumerate(show, 1):
        ui.info(ui.c(f"{i:>2}. {info.subnet}", ui.H))
        ui.info(f"    Netzwerk   : {info.network}")
        ui.info(f"    Broadcast  : {info.broadcast}")
        ui.info(f"    Hostrange  : {info.first_host}  –  {info.last_host}")
        ui.info(f"    Hosts      : {info.usable_hosts}")
        ui.info(f"    Maske      : {info.netmask}   Wildcard: {info.wildcard}")
        ui.info(f"    Magic      : {info.magic_number} (Oktett {info.interesting_octet})")
        ui.info("")

    if limit is not None and len(infos) > limit:
        ui.warn(f"(Anzeige gekürzt: {limit} von {len(infos)} Subnetzen. Export enthält alle.)")

def export_markdown_and_csv(
    ui: UI,
    base: ipaddress.IPv4Network,
    mode_name: str,
    infos: list[SubnetInfo],
    out_dir: Path | None = None,
) -> tuple[Path, Path]:
    out_dir = out_dir or Path.home() / "Downloads"
    out_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    md_path = out_dir / f"subnet_{mode_name}_{ts}.md"
    csv_path = out_dir / f"subnet_{mode_name}_{ts}.csv"

    # Markdown (didaktische Notiz)
    lines: list[str] = []
    lines.append(f"# Subnetting Export ({mode_name})")
    lines.append("")
    lines.append(f"- Datum/Zeit: {datetime.now().isoformat(timespec='seconds')}")
    lines.append(f"- Ausgangsnetz: `{base}`")
    lines.append("")
    lines.append("| Subnetz | Netz | Broadcast | First Host | Last Host | Hosts | Maske | Wildcard | Magic |")
    lines.append("|---|---|---|---|---|---:|---|---|---:|")
    for x in infos:
        lines.append(
            f"| `{x.subnet}` | `{x.network}` | `{x.broadcast}` | `{x.first_host}` | `{x.last_host}` | {x.usable_hosts} | `{x.netmask}` | `{x.wildcard}` | {x.magic_number} |"
        )
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # CSV
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow([
            "Subnetz", "Netzwerk", "Broadcast", "Erster Host", "Letzter Host", "Nutzbare Hosts",
            "Maske", "Wildcard", "Magic Number", "Interessantes Oktett"
        ])
        for x in infos:
            w.writerow([
                x.subnet, x.network, x.broadcast, x.first_host, x.last_host, x.usable_hosts,
                x.netmask, x.wildcard, x.magic_number, x.interesting_octet
            ])

    ui.success(f"✔ Exportiert:\n  MD : {md_path}\n  CSV: {csv_path}")
    return md_path, csv_path


# ============================================================
# 7) Menü-Aktionen
# ============================================================

def action_split_by_n(ui: UI) -> None:
    ui.headline("1) Netzwerk in N Subnetze aufteilen")
    base = ask_net(ui, "Ausgangsnetz (z.B. 192.168.1.0/24): ")
    n = ask_int(ui, "Wie viele Subnetze brauchst du (N)?: ", min_v=1)

    new_prefix, subs, borrowed_bits = subnet_by_count(base, n)
    ui.info("")
    ui.info(f"Borrowed Bits: {borrowed_bits}  (ceil(log2({n})) = {borrowed_bits})")
    print_summary(ui, base, new_prefix)

    infos = [describe_subnet(s) for s in subs]
    ui.info("")
    print_subnets(ui, infos, limit=64)

    if yes_no("Exportieren (MD+CSV) nach ~/Downloads? (j/n): "):
        export_markdown_and_csv(ui, base, "by_count", infos)

def action_split_by_prefix(ui: UI) -> None:
    ui.headline("2) Netzwerk auf Ziel-Präfix /xx aufteilen")
    base = ask_net(ui, "Ausgangsnetz (z.B. 10.0.0.0/16): ")
    new_prefix = ask_int(ui, "Ziel-Präfix (z.B. 24): ", min_v=0, max_v=32)

    if new_prefix < base.prefixlen:
        ui.error(f"Nicht möglich: Ziel-Präfix /{new_prefix} ist kleiner als Ausgang /{base.prefixlen}.")
        return

    subs = list(base.subnets(new_prefix=new_prefix))
    print_summary(ui, base, new_prefix)

    infos = [describe_subnet(s) for s in subs]
    ui.info("")
    print_subnets(ui, infos, limit=64)

    if yes_no("Exportieren (MD+CSV) nach ~/Downloads? (j/n): "):
        export_markdown_and_csv(ui, base, "by_prefix", infos)

def action_split_by_hosts(ui: UI) -> None:
    ui.headline("3) Subnetze nach benötigten Hosts/Subnetz")
    base = ask_net(ui, "Ausgangsnetz (z.B. 172.16.0.0/20): ")
    hosts = ask_int(ui, "Benötigte nutzbare Hosts pro Subnetz: ", min_v=1)

    new_prefix, subs, host_bits = subnet_by_hosts(base, hosts)

    ui.info("")
    ui.info(f"Host Bits: {host_bits}  (ceil(log2({hosts}+2)) = {host_bits})")
    print_summary(ui, base, new_prefix)

    infos = [describe_subnet(s) for s in subs]
    ui.info("")
    print_subnets(ui, infos, limit=64)

    if yes_no("Exportieren (MD+CSV) nach ~/Downloads? (j/n): "):
        export_markdown_and_csv(ui, base, "by_hosts", infos)

def action_ip_in_subnet(ui: UI) -> None:
    ui.headline("4) IP prüfen: In welches Subnetz fällt eine IP?")
    base = ask_net(ui, "Ausgangsnetz (z.B. 192.168.1.0/24): ")
    target_prefix = ask_int(ui, "Subnetz-Präfix, gegen das du prüfen willst (z.B. 27): ", min_v=0, max_v=32)

    if target_prefix < base.prefixlen:
        ui.error(f"Ziel-Präfix /{target_prefix} ist größerer Bereich als Ausgang /{base.prefixlen}.")
        ui.error("Das ergibt hier keinen Sinn. Nimm ein Präfix >= Ausgangspräfix.")
        return

    ip = ask_ip(ui, "IP-Adresse (z.B. 192.168.1.130): ")

    subs = list(base.subnets(new_prefix=target_prefix))
    hit = None
    for s in subs:
        if ip in s:
            hit = s
            break

    if hit is None:
        ui.warn(f"IP {ip} liegt NICHT im Ausgangsnetz {base}.")
        return

    info = describe_subnet(hit)
    ui.success(f"Treffer: IP {ip} liegt in Subnetz {info.subnet}")
    ui.info(f"Netzwerk   : {info.network}")
    ui.info(f"Broadcast  : {info.broadcast}")
    ui.info(f"Hostrange  : {info.first_host} – {info.last_host}")
    ui.info(f"Maske      : {info.netmask}  Wildcard: {info.wildcard}")
    ui.info(f"Magic      : {info.magic_number} (Oktett {info.interesting_octet})")

def action_analyze_network(ui: UI) -> None:
    ui.headline("5) Ein Subnetz analysieren (Netz/Broadcast/Hosts/Maske)")
    net = ask_net(ui, "IP/CIDR (z.B. 192.168.1.10/27 oder 10.0.0.0/8): ")
    info = describe_subnet(net)

    ui.info(ui.c(f"{info.subnet}", ui.H))
    ui.info(f"Netzwerk   : {info.network}")
    ui.info(f"Broadcast  : {info.broadcast}")
    ui.info(f"Hostrange  : {info.first_host} – {info.last_host}")
    ui.info(f"Hosts      : {info.usable_hosts}")
    ui.info(f"Maske      : {info.netmask}")
    ui.info(f"Wildcard   : {info.wildcard}")
    ui.info(f"Magic      : {info.magic_number} (Oktett {info.interesting_octet}, Maskenwert {info.mask_octet_value})")


# ============================================================
# 8) Main (Menü)
# ============================================================

def parse_args(argv: list[str]) -> bool:
    """Sehr leichtes Arg-Parsing: --no-color"""
    return "--no-color" not in argv

def main() -> None:
    use_color = parse_args(sys.argv[1:])
    ui = UI(use_color=use_color)

    ui.headline("IPv4 Subnetting Tool – LPIC / IHK / CompTIA (Ferrari Edition)")
    ui.info("Hinweis: Farben aus = starte mit:  python3 subnetear.py --no-color\n")

    while True:
        ui.info(ui.c("Menü:", ui.H))
        ui.info("  1) Netzwerk in N Subnetze aufteilen")
        ui.info("  2) Netzwerk auf Ziel-Präfix /xx aufteilen")
        ui.info("  3) Subnetze nach Hosts/Subnetz")
        ui.info("  4) IP -> Subnetz (innerhalb eines Ausgangsnetzes)")
        ui.info("  5) Subnetz analysieren")
        ui.info("  0) Beenden")

        choice = input("\nAuswahl: ").strip()

        if choice == "1":
            action_split_by_n(ui)
        elif choice == "2":
            action_split_by_prefix(ui)
        elif choice == "3":
            action_split_by_hosts(ui)
        elif choice == "4":
            action_ip_in_subnet(ui)
        elif choice == "5":
            action_analyze_network(ui)
        elif choice == "0":
            ui.success("Bis dann. Sauber subnetten. 🧠")
            return
        else:
            ui.error("Ungültige Auswahl. Bitte 0–5.")

        # Kleine Pause/Trennlinie
        print("")

if __name__ == "__main__":
    main()
