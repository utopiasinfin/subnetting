#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
subnetear.py – IPv4-Ipv6- Subnetting-Trainer (LPIC / IHK / CompTIA Stil)

Didaktische Ziele:
- Rechnen + Verstehen: nicht nur Ergebnis, sondern Herleitung.
- IHK-/CompTIA-orientierte Methodik: Borrowed Bits, Host Bits, Magic Number.
- Tutor-Modus: Tipps, Prüfungsfallen, Merkhilfen in jedem Programmbereich.
"""

from __future__ import annotations

import csv
import ipaddress
import math
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


class UI:
    def __init__(self, use_color: bool = True) -> None:
        self.use_color = use_color and sys.stdout.isatty()

    def c(self, text: str, code: str) -> str:
        if not self.use_color:
            return text
        return f"\033[{code}m{text}\033[0m"

    @property
    def H(self) -> str:
        return "1;36"

    @property
    def OK(self) -> str:
        return "1;32"

    @property
    def WRN(self) -> str:
        return "1;33"

    @property
    def ERR(self) -> str:
        return "1;31"

    @property
    def DIM(self) -> str:
        return "2"

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

    def tutor_box(self, title: str, lines: list[str]) -> None:
        self.info(self.c(f"\n🧑‍🏫 {title}", self.H))
        for line in lines:
            self.info(f"   {line}")


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
    total_addresses: int
    borrowed_bits: int
    host_bits: int
    magic_number: int
    interesting_octet: int
    mask_octet_value: int


def mask_from_prefix(prefix: int) -> str:
    return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)


def wildcard_from_mask(mask: str) -> str:
    return ".".join(str(255 - int(o)) for o in mask.split("."))


def to_binary(octets: tuple[int, ...]) -> str:
    return " ".join(f"{o:08b}" for o in octets)


def ip_to_binary(ip: str) -> str:
    return to_binary(tuple(map(int, ip.split("."))))


def mask_to_binary(mask: str) -> str:
    return to_binary(tuple(map(int, mask.split("."))))


def block_size(prefix: int) -> int:
    return 2 ** (32 - prefix)


def interesting_octet(prefix: int) -> tuple[int, int, int]:
    netmask = ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask
    octets = list(map(int, str(netmask).split(".")))
    if prefix == 0:
        return 256, 1, 0
    if prefix % 8 == 0:
        return 1, prefix // 8, 255
    idx = prefix // 8
    mask_oct = octets[idx]
    magic = 256 - mask_oct
    return magic, idx + 1, mask_oct


def calc_host_capacity(prefix: int) -> tuple[int, int, int]:
    total = 2 ** (32 - prefix)
    if prefix <= 30:
        return total, max(total - 2, 0), 32 - prefix
    if prefix == 31:
        return total, 2, 1
    return total, 1, 0


def describe_subnet(net: ipaddress.IPv4Network, borrowed_bits: int = 0) -> SubnetInfo:
    total, usable, host_bits = calc_host_capacity(net.prefixlen)
    netmask = str(net.netmask)
    wildcard = wildcard_from_mask(netmask)
    magic, oct_no, mask_oct = interesting_octet(net.prefixlen)

    if net.prefixlen <= 30:
        first = str(net.network_address + 1)
        last = str(net.broadcast_address - 1)
    elif net.prefixlen == 31:
        first = str(net.network_address)
        last = str(net.broadcast_address)
    else:
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
        total_addresses=total,
        borrowed_bits=borrowed_bits,
        host_bits=host_bits,
        magic_number=magic,
        interesting_octet=oct_no,
        mask_octet_value=mask_oct,
    )


def subnet_by_count(net: ipaddress.IPv4Network, n: int) -> tuple[int, list[ipaddress.IPv4Network], int]:
    if n <= 0:
        raise ValueError("N muss >= 1 sein.")
    borrowed_bits = math.ceil(math.log2(n)) if n > 1 else 0
    new_prefix = net.prefixlen + borrowed_bits
    if new_prefix > 32:
        raise ValueError("Zu viele Subnetze: Präfix würde > /32 werden.")
    return new_prefix, list(net.subnets(new_prefix=new_prefix)), borrowed_bits


def subnet_by_hosts(net: ipaddress.IPv4Network, hosts: int) -> tuple[int, list[ipaddress.IPv4Network], int]:
    if hosts <= 0:
        raise ValueError("Hosts müssen >= 1 sein.")

    if hosts == 1:
        host_bits = 0
        new_prefix = 32
    elif hosts == 2:
        host_bits = 1
        new_prefix = 31
    else:
        host_bits = math.ceil(math.log2(hosts + 2))
        new_prefix = 32 - host_bits

    if new_prefix < net.prefixlen:
        raise ValueError("Nicht möglich: gewünschte Hostanzahl passt nicht in das Ausgangsnetz.")

    return new_prefix, list(net.subnets(new_prefix=new_prefix)), host_bits


def ask_int(ui: UI, prompt: str, min_v: int = 1, max_v: int | None = None) -> int | None:
    while True:
        try:
            raw = input(prompt).strip()
        except EOFError:
            return None
        except KeyboardInterrupt:
            return None

        if raw.lower() in ("b", "back", "q", "quit", ""):
            return None
        try:
            value = int(raw)
            if value < min_v:
                ui.error(f"Ungültig: Zahl muss >= {min_v} sein.")
                continue
            if max_v is not None and value > max_v:
                ui.error(f"Ungültig: Zahl muss <= {max_v} sein.")
                continue
            return value
        except ValueError:
            ui.error("Ungültige Zahl. Beispiel: 8 (oder 'b' für Zurück)")


def ask_net(ui: UI, prompt: str) -> ipaddress.IPv4Network | None:
    while True:
        raw = input(prompt).strip()

        if raw.lower() in ("b", "back", "q", "quit", ""):
            return None

        if "/" not in raw:
            ui.error("Bitte CIDR-Notation mit Präfix eingeben (z.B. 192.168.1.0/24).")
            ui.tutor_box(
                "Warum Präfix Pflicht ist",
                [
                    "Ohne /Präfix kann das Tool nicht wissen, wie groß das Ausgangsnetz ist.",
                    "Beispiel: 192.168.1.0 kann /24, /25 oder /30 sein – das sind komplett andere Aufgaben.",
                ],
            )
            continue

        try:
            net = ipaddress.ip_network(raw, strict=False)
            if not isinstance(net, ipaddress.IPv4Network):
                ui.error("Bitte nur IPv4 (z.B. 192.168.1.0/24).")
                continue
            return net
        except ValueError:
            ui.error("Ungültiges Format. Beispiel: 192.168.1.0/24 (oder 'b' für Zurück)")


def ask_ip(ui: UI, prompt: str) -> ipaddress.IPv4Address | None:
    while True:
        raw = input(prompt).strip()

        if raw.lower() in ("b", "back", "q", "quit", ""):
            return None

        try:
            ip = ipaddress.ip_address(raw)
            if not isinstance(ip, ipaddress.IPv4Address):
                ui.error("Bitte nur IPv4 (z.B. 192.168.1.10).")
                continue
            return ip
        except ValueError:
            ui.error("Ungültige IPv4-Adresse. Beispiel: 10.0.0.5 (oder 'b' für Zurück)")


def yes_no(prompt: str) -> bool:
    return input(prompt).strip().lower().startswith(("j", "y", "s"))


IPv6_TRICKS = {
    64: ("/64", "Standard LAN", "18.446.744.073.709.551.616 Hosts", "Empfohlen für LAN"),
    48: ("/48", "Site Prefix", "1.208.925.819.614.629.174.706.176 Hosts", "ISP vergibt /48 bis /52"),
    56: ("/56", "Small Site", "4.722.366.482.869.645.213.696 Hosts", "Typisch für Home"),
    126: ("/126", "P2P Link", "4 Hosts", "Router-Router"),
    127: ("/127", "P2P Link", "2 Hosts", "WAN Link"),
    128: ("/128", "Single Host", "1 Host", "Loopback/Interface"),
}


def print_ipv6_tricks(ui: UI, prefix: int) -> None:
    ui.tutor_box(
        "🧮 IPv6 Rechen-Tricks",
        [
            "Host-Bits = 128 - Präfix",
            "/64 = 65.536 TB (praktisch unendlich für LAN)",
            "Vereinfachung: /64 = 2^64 = 18.4 Trillionen Hosts",
            "Nur Subnetze: /48 vergibt 65.536 /64er pro Site",
            "Unique Local: fc00::/7 (fd00::/8) = Private",
            "Link-Local: fe80::/10 = Nur lokal",
        ],
    )

    if prefix in IPv6_TRICKS:
        bits, name, hosts, note = IPv6_TRICKS[prefix]
        ui.tutor_box(
            f"Schnellinfo: /{prefix}",
            [
                f"Typ: {name}",
                f"Hosts: {hosts}",
                f"Tipp: {note}",
            ],
        )


def describe_ipv6_subnet(net: ipaddress.IPv6Network) -> dict:
    prefix = net.prefixlen
    host_bits = 128 - prefix
    total = 2 ** host_bits

    return {
        "subnet": str(net),
        "network": str(net.network_address),
        "first_host": str(net.network_address),
        "last_host": str(net.broadcast_address) if prefix < 128 else str(net.network_address),
        "total_addresses": total,
        "prefix": prefix,
        "host_bits": host_bits,
    }


def action_ipv6_analyze(ui: UI) -> None:
    ui.headline("6) IPv6 Subnetz analysieren")
    ui.info("IPv6 nutzt 128 Bits (statt 32 bei IPv4)\n")

    while True:
        raw = input("IPv6 CIDR (z.B. 2001:db8::/64) oder 'b' für Zurück: ").strip()
        if raw.lower() in ("b", "back", ""):
            return

        try:
            net = ipaddress.ip_network(raw, strict=False)
            if not isinstance(net, ipaddress.IPv6Network):
                ui.error("Bitte IPv6 eingeben (z.B. 2001:db8::/64)")
                continue
            break
        except ValueError:
            ui.error("Ungültiges Format. Beispiel: 2001:db8::/64")

    info = describe_ipv6_subnet(net)

    ui.info(ui.c(f"\n{info['subnet']}", ui.H))
    ui.info(f"Netzwerk : {info['network']}")
    ui.info(f"Host-Bits: {info['host_bits']}")
    ui.info(f"Adressen: {info['total_addresses']:,}")

    ui.tutor_box(
        "IPv6 Binär-Darstellung",
        [
            f"Präfix  : {'1' * info['prefix']}{'0' * info['host_bits']}",
            f"         {'|--- Netz ---'}{'--- Host ---'[:info['host_bits']//4]}",
        ]
    )

    ui.tutor_box(
        "🧑‍🏫 IPv6 Erklärung",
        [
            f"/{info['prefix']} bedeutet: {info['host_bits']} Host-Bits",
            "IPv6 hat keine Broadcast-Adressen",
            "Jede Interface hat mehrere IPs: Link-Local, Global, Unique Local",
            "/64 ist Standard für LAN (SLAAC)",
            "Doppelter Doppelpunkt (::) fasst Nullen zusammen",
        ]
    )

    print_ipv6_tricks(ui, info['prefix'])


def action_ipv6_subnet(ui: UI) -> None:
    ui.headline("7) IPv6 Netz in Subnetze aufteilen")

    while True:
        raw = input("Ausgangsnetz IPv6 (z.B. 2001:db8::/32) oder 'b' für Zurück: ").strip()
        if raw.lower() in ("b", "back", ""):
            return

        try:
            base = ipaddress.ip_network(raw, strict=False)
            if not isinstance(base, ipaddress.IPv6Network):
                ui.error("Bitte IPv6 eingeben")
                continue
            break
        except ValueError:
            ui.error("Ungültiges Format")

    new_prefix = ask_int(ui, "Ziel-Präfix (z.B. 48): ", min_v=0, max_v=128)
    if new_prefix is None:
        return

    if new_prefix < base.prefixlen:
        ui.error("Ziel-Präfix muss größer oder gleich Ausgangspräfix sein.")
        return

    borrowed = new_prefix - base.prefixlen
    num_subnets = 2 ** borrowed

    if num_subnets > 10000:
        ui.warn(f"Warnung: {num_subnets:,} Subnetze - zeige nur die ersten 20")

    ui.info(f"\nAusgang     : {base}")
    ui.info(f"Zielpräfix  : /{new_prefix}")
    ui.info(f"Borrowed    : {borrowed} Bits")
    ui.info(f"Subnetze    : {num_subnets:,}")

    ui.tutor_box(
        "🧮 IPv6 Subnetting",
        [
            f"Jedes zusätzliche Bit verdoppelt die Subnetze",
            f"{borrowed} Bits = 2^{borrowed} = {num_subnets:,} Subnetze",
            "Host-Bits = 128 - /48 = 80 (pro Subnetz)",
            "/48 kann 65.536 /64er Subnetze aufteilen",
        ]
    )

    ui.info("\nErste 20 Subnetze:")
    subs = list(base.subnets(new_prefix=new_prefix))
    for i, s in enumerate(subs[:20], 1):
        ui.info(f"  {i:>2}. {s}")

    if len(subs) > 20:
        ui.warn(f"  ... und {len(subs) - 20} weitere (zu viele für Anzeige)")


import random


def quiz_question(ui: UI, question_type: str) -> bool:
    if question_type == "hosts":
        prefix = random.randint(8, 30)
        total = 2 ** (32 - prefix)
        usable = total - 2 if prefix < 31 else (2 if prefix == 31 else 1)

        ui.info(f"\nFrage: Wie viele nutzbare Hosts hat /{prefix}?")
        answer = input("Antwort: ").strip()

        try:
            if int(answer) == usable:
                ui.success("✅ Richtig!")
                return True
            else:
                ui.error(f"❌ Falsch. Richtig: {usable} (bei {total} Adressen)")
                return False
        except ValueError:
            ui.error(f"❌ Falsch. Richtig: {usable}")
            return False

    elif question_type == "magic":
        prefixes = [24, 25, 26, 27, 28, 29, 30]
        prefix = random.choice(prefixes)
        magic = 2 ** (8 - (prefix % 8))

        ui.info(f"\nFrage: Was ist die Magic Number für /{prefix}?")
        answer = input("Antwort: ").strip()

        try:
            if int(answer) == magic:
                ui.success("✅ Richtig!")
                return True
            else:
                ui.error(f"❌ Falsch. Richtig: {magic}")
                return False
        except ValueError:
            ui.error(f"❌ Falsch. Richtig: {magic}")
            return False

    elif question_type == "network":
        base = random.choice([
            "192.168.1.0/24",
            "10.0.0.0/16",
            "172.16.0.0/12",
        ])
        net = ipaddress.ip_network(base)
        change = random.randint(1, 3)
        subnets = list(net.subnets(new_prefix=net.prefixlen + change))
        target = random.choice(subnets)
        ip = random.choice(list(target.hosts()))

        ui.info(f"\nFrage: In welchem Subnetz liegt {ip} (innerhalb von {base})?")
        answer = input("Antwort (CIDR, z.B. 192.168.1.0/26): ").strip()

        if answer == str(target):
            ui.success("✅ Richtig!")
            return True
        else:
            ui.error(f"❌ Falsch. Richtig: {target}")
            return False

    elif question_type == "binary":
        ip = ipaddress.IPv4Address(random.randint(1, 223 * 256**3))

        ui.info(f"\nFrage: Was ist {ip} in Binär?")
        ui.info("Antwort mit Punkten, z.B. 11000000.10101000.00000001.00000001")
        answer = input("Antwort: ").strip()

        expected = ip_to_binary(str(ip))
        if answer.replace(" ", "") == expected.replace(" ", ""):
            ui.success("✅ Richtig!")
            return True
        else:
            ui.error(f"❌ Falsch. Richtig: {expected}")
            return False

    return False


def action_quiz(ui: UI) -> None:
    ui.headline("🔢 Quiz: Teste dein Wissen!")

    question_types = [
        ("Host-Berechnung", "hosts"),
        ("Magic Number", "magic"),
        ("IP in Subnetz", "network"),
        ("Binär-Umrechnung", "binary"),
    ]

    correct = 0
    total = 0

    ui.info("4 Fragen pro Runde. Viel Erfolg!\n")
    ui.info("Frage-Typen:")
    for name, _ in question_types:
        ui.info(f"  - {name}")

    rounds = ask_int(ui, "\nWie viele Runden? ", min_v=1, max_v=10)
    if rounds is None:
        return

    for r in range(rounds):
        q_type = random.choice(question_types)
        name, code = q_type
        ui.info(f"\n{'='*40}")
        ui.info(f"Runde {r+1}/{rounds}: {name}")
        try:
            if quiz_question(ui, code):
                correct += 1
            total += 1
        except (EOFError, KeyboardInterrupt):
            ui.info("\nQuiz abgebrochen.")
            break

    if total > 0:
        ui.success(f"\n🎉 Ergebnis: {correct}/{total} richtig!")
        if correct == total:
            ui.success("Perfekt! Du bist bereit für die Prüfung!")
        elif correct >= total * 0.75:
            ui.info("Gut gemacht! Weiter üben!")
        else:
            ui.warn("Nochmal üben! Nutze die Tutor-Modi.")


@dataclass(frozen=True)
class VLSMSubnet:
    name: str
    network: ipaddress.IPv4Network
    hosts_needed: int
    usable: int


def action_vlsm(ui: UI) -> None:
    ui.headline("9) VLSM: Variable Length Subnet Mask")

    ui.tutor_box(
        "Was ist VLSM?",
        [
            "VLSM = VerschiedeneSubnetz-Größen im gleichen Netz",
            "Beispiel: Netz 192.168.1.0/24 aufteilen für:",
            "  - 100 Hosts (braucht /25 = 126)",
            "  - 50 Hosts (braucht /26 = 62)",
            "  - 25 Hosts (braucht /27 = 30)",
            "  - 10 Hosts (braucht /28 = 14)",
            "Wichtig: Größte Subnetze ZUERST zuweisen!",
        ],
    )

    base = ask_net(ui, "Ausgangsnetz (z.B. 192.168.1.0/24): ")
    if base is None:
        return

    ui.info("\nGib Subnetze ein (Name + Hosts).Leerzeile beendet.")
    ui.info("Beispiel: Server 50")
    ui.info("          Client 100")
    ui.info("          Router 5\n")

    subnets_input: list[tuple[str, int]] = []

    while True:
        line = input("Subnetz (Name Hosts) oder leer: ").strip()
        if not line:
            break

        parts = line.split()
        if len(parts) < 2:
            ui.error("Format: Name Anzahl")
            continue

        try:
            name = parts[0]
            hosts = int(parts[1])
            subnets_input.append((name, hosts))
        except ValueError:
            ui.error("Zahl fehlt: Beispiel 'Server 50'")

    if not subnets_input:
        ui.warn("Keine Subnetze eingegeben.")
        return

    subnets_input.sort(key=lambda x: x[1], reverse=True)

    ui.tutor_box(
        "VLSM Berechnung",
        [
            "1. Sortiere nach Größe (größte zuerst)",
            "2. Berechne benötigte Host-Bits",
            "3. Ordne von oben nach unten zu",
        ],
    )

    ui.info("\n" + "=" * 60)
    ui.info("VLSM Ergebnis:")
    ui.info("=" * 60)

    vlsm_subnets: list[VLSMSubnet] = []
    current = base.network_address

    for name, hosts_needed in subnets_input:
        host_bits = math.ceil(math.log2(hosts_needed + 2))
        prefix = 32 - host_bits
        total_addr = 2 ** host_bits
        usable = total_addr - 2 if prefix < 31 else (2 if prefix == 31 else 1)

        net = ipaddress.IPv4Network(f"{current}/{prefix}", strict=False)

        ui.info(f"\n{name}:")
        ui.info(f"  Braucht: {hosts_needed} Hosts")
        ui.info(f"  Netz    : {net}")
        ui.info(f"  Prefix  : /{prefix}")
        ui.info(f"  Hosts   : {usable} (davon nutzbar)")
        ui.info(f"  Bereich : {net.network_address} - {net.broadcast_address}")

        vlsm_subnets.append(VLSMSubnet(
            name=name,
            network=net,
            hosts_needed=hosts_needed,
            usable=usable,
        ))

        current = net.broadcast_address + 1

    ui.info("\n" + "=" * 60)
    ui.info("Zusammenfassung:")
    for s in vlsm_subnets:
        ui.info(f"  {s.name:12} {str(s.network):18} /{s.network.prefixlen}  ({s.usable} Hosts)")

    used = sum(s.usable for s in vlsm_subnets)
    total_available = 2 ** (32 - base.prefixlen)
    ui.info(f"\nGenutzt: {used} von {total_available} möglichen Hosts")


def print_tutor_intro(ui: UI) -> None:
    ui.tutor_box(
        "Subnetting-Denkmodell (IHK/CompTIA)",
        [
            "1) Fragestellung klären: Anzahl Subnetze ODER Hosts pro Subnetz?",
            "2) Präfix bestimmen: Borrowed Bits oder Host Bits berechnen.",
            "3) Neue Maske lesen: interessantes Oktett + Magic Number erkennen.",
            "4) Blocksprung nutzen: Netzadressen in Schritten der Magic Number.",
            "5) Pro Subnetz prüfen: Netz, Broadcast, Hostbereich, nutzbare Hosts.",
        ],
    )


def print_summary(ui: UI, base: ipaddress.IPv4Network, new_prefix: int, borrowed_bits: int = 0) -> None:
    total, usable, host_bits = calc_host_capacity(new_prefix)
    mask = mask_from_prefix(new_prefix)
    magic, oct_no, mask_oct = interesting_octet(new_prefix)

    ui.info(f"Ausgangsnetz : {base}")
    ui.info(f"Neue Maske   : {mask}  (/{new_prefix})")
    ui.info(f"Wildcard     : {wildcard_from_mask(mask)}")
    ui.info(f"Host Bits    : {host_bits}")
    ui.info(f"Borrowed Bits: {borrowed_bits}")
    ui.info(f"Blockgröße   : {block_size(new_prefix)} Adressen pro Subnetz")
    ui.info(f"Nutzbare Hosts/Subnetz: {usable} (gesamt {total})")
    ui.info(f"Magic Number : {magic} (im {oct_no}. Oktett, Maskenwert {mask_oct})")

    ui.tutor_box(
        "Schritt-für-Schritt Erklärung", [
            f"1. Host-Bits = 32 - /{new_prefix} = {host_bits}",
            f"2. Adressen/Subnetz = 2^{host_bits} = {total}",
            f"3. Nutzbare Hosts = {total} - 2 = {usable} (bei /31, /32 Sonderfall)",
            f"4. Magic Number = 256 - {mask_oct} = {magic}",
            f"5. Netzadressen: immer +{magic} im {oct_no}. Oktett",
        ]
    )

    ui.tutor_box(
        "Warum das stimmt", [
            f"Host Bits = 32 - {new_prefix} = {host_bits}.",
            f"Adressen pro Subnetz = 2^{host_bits} = {total}.",
            "Bei /0 bis /30 sind nutzbare Hosts = Gesamtadressen - 2 (Netz/Broadcast).",
            "Sonderfälle: /31 (P2P) hat 2 nutzbare Adressen, /32 genau 1 Adresse.",
        ]
    )


def print_subnets(ui: UI, infos: list[SubnetInfo], limit: int | None = None) -> None:
    show = infos if limit is None else infos[:limit]
    for i, info in enumerate(show, 1):
        ui.info(ui.c(f"{i:>2}. {info.subnet}", ui.H))
        ui.info(f"    Netzwerk   : {info.network}")
        ui.info(f"    Broadcast  : {info.broadcast}")
        ui.info(f"    Hostrange  : {info.first_host}  –  {info.last_host}")
        ui.info(f"    Hosts      : {info.usable_hosts} (gesamt {info.total_addresses})")
        ui.info(f"    Maske      : {info.netmask}   Wildcard: {info.wildcard}")
        ui.info(f"    Magic      : {info.magic_number} (Oktett {info.interesting_octet})")
        ui.info("")

    if limit is not None and len(infos) > limit:
        ui.warn(f"(Anzeige gekürzt: {limit} von {len(infos)} Subnetzen. Export enthält alle.)")


def print_exam_tips(ui: UI) -> None:
    ui.tutor_box(
        "Prüfungs-Tipps & typische Fallen",
        [
            "Merksatz: Mehr Subnetze => Präfix wird größer => weniger Hosts pro Subnetz.",
            "CompTIA-Falle: Erst fragen, ob 'brauchbare Hosts' oder 'Gesamtadressen' gemeint sind.",
            "IHK-Falle: Bei /31 und /32 Sonderbehandlung sauber begründen.",
            "Netzsprung schnell: im interessanten Oktett immer +Magic Number zählen.",
        ],
    )


TRICKS = {
    24: ("Klasse C", "255.255.255.0", "256 Hosts", "Typisch für LAN"),
    16: ("Klasse B", "255.255.0.0", "65.536 Hosts", "Typisch für Campus"),
    8: ("Klasse A", "255.0.0.0", "16.777.216 Hosts", "Typisch für ISP"),
    32: ("Single Host", "255.255.255.255", "1 Host", "P2P oder Loopback"),
    31: ("P2P-Link", "255.255.255.254", "2 Hosts", "Kein Netz/Broadcast"),
    30: ("P2P-Link", "255.255.255.252", "2 nutzbare", "Klassisch für Router"),
    27: ("Small LAN", "255.255.255.224", "30 Hosts", "Typisch für VLANs"),
    28: ("Small LAN", "255.255.255.240", "14 Hosts", "Kleine Teams"),
    29: ("P2P", "255.255.255.248", "6 Hosts", "Wenige Links"),
}


def print_tricks(ui: UI, prefix: int) -> None:
    if prefix in TRICKS:
        name, mask, hosts, note = TRICKS[prefix]
        ui.tutor_box(
            f"Schnellinfo: /{prefix}",
            [
                f"Typ: {name}",
                f"Maske: {mask}",
                f"Hosts: {hosts}",
                f"Tipp: {note}",
            ],
        )

    ui.tutor_box(
        "🧮 Rechen-Tricks für die Prüfung",
        [
            "Magic Number = 256 - Maskenwert im interessanten Oktett",
            "Blocksprung: Netzadressen immer +Magic Number",
            "Host-Bits merken: /24→8, /25→7, /26→6, /27→5, /28→4, /29→3, /30→2",
            "Kurz: Host-Bits = 32 - Präfix",
            "Nützlich: 2^10 = 1024 ≈ 1000 (Kilo), 2^20 ≈ 1.000.000 (Mega)",
            "Schnell: /16 = 65.536, /24 = 256, /30 = 4, /32 = 1",
        ],
    )


def print_classful_context(ui: UI, net: ipaddress.IPv4Network) -> None:
    p = net.prefixlen
    if p <= 8:
        klasse = "A"
        default = "/8"
    elif p <= 16:
        klasse = "B"
        default = "/16"
    elif p <= 24:
        klasse = "C"
        default = "/24"
    else:
        klasse = "Kleiner als C"
        default = f"/{p}"

    ui.tutor_box(
        "🕰️ Historischer Klassen-Kontext",
        [
            f"Klasse {klasse} (historisch) - Default-Maske: {default}",
            "Heute: CIDR (Classless) - Klasse egal",
            "/8 = 16.777.216 (Klasse A), /16 = 65.536 (Klasse B), /24 = 256 (Klasse C)",
        ],
    )

    print_tricks(ui, net.prefixlen)


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

    lines: list[str] = [
        f"# Subnetting-Export ({mode_name})",
        "",
        f"- Datum/Zeit: {datetime.now().isoformat(timespec='seconds')}",
        f"- Ausgangsnetz: `{base}`",
        "",
        "## Didaktische Kurz-Zusammenfassung",
        "- Vorgehen: Ziel klären -> Präfix berechnen -> Magic Number -> Subnetze prüfen.",
        "- Prüfen: Netzwerkadresse, Broadcast, Hostbereich und nutzbare Hosts.",
        "",
        "| Subnetz | Netz | Broadcast | First Host | Last Host | Nutzbare Hosts | Gesamtadressen | Maske | Wildcard | Magic |",
        "|---|---|---|---|---|---:|---:|---|---|---:|",
    ]

    for x in infos:
        lines.append(
            f"| `{x.subnet}` | `{x.network}` | `{x.broadcast}` | `{x.first_host}` | `{x.last_host}` | {x.usable_hosts} | {x.total_addresses} | `{x.netmask}` | `{x.wildcard}` | {x.magic_number} |"
        )

    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow([
            "Subnetz", "Netzwerk", "Broadcast", "Erster Host", "Letzter Host", "Nutzbare Hosts",
            "Gesamtadressen", "Maske", "Wildcard", "Magic Number", "Interessantes Oktett", "Host Bits", "Borrowed Bits"
        ])
        for x in infos:
            w.writerow([
                x.subnet, x.network, x.broadcast, x.first_host, x.last_host, x.usable_hosts,
                x.total_addresses, x.netmask, x.wildcard, x.magic_number, x.interesting_octet, x.host_bits, x.borrowed_bits
            ])

    ui.success(f"✔ Exportiert:\n  MD : {md_path}\n  CSV: {csv_path}")
    return md_path, csv_path


def action_split_by_n(ui: UI) -> None:
    ui.headline("1) Netzwerk in N Subnetze aufteilen (Lerne: Mechanismus!)")
    
    ui.tutor_box(
        "🎓 LERNEN: Wie funktioniert Subnetting?",
        [
            "Subnetting = Netz in kleinere Stücke teilen",
            "Wir 'borgen' Bits von den Host-Bits für neue Subnetze",
            "Mehr Subnetze = weniger Hosts pro Subnetz",
            "",
            "Schritte:",
            "1. Frage: Wie viele Subnetze willst du?",
            "2. Berechne: Wieviele Bits brauchen wir? → 2^Bits ≥ N",
            "3. Neues Präfix = altes Präfix + geborgte Bits",
            "4. Jedes zusätzliche Bit verdoppelt die Anzahl der Subnetze",
        ]
    )

    base = ask_net(ui, "Ausgangsnetz (z.B. 192.168.1.0/24): ")
    if base is None:
        return
    
    ui.info(f"\n📌 Dein Netz: {base}")
    ui.info(f"   Präfix: /{base.prefixlen}")
    ui.info(f"   Host-Bits: {32 - base.prefixlen}")
    ui.info(f"   Hosts maximal: {2**(32-base.prefixlen) - 2}")
    
    n = ask_int(ui, "\nWie viele Subnetze brauchst du? ", min_v=1)
    if n is None:
        return

    ui.tutor_box(
        "🧮 Schritt 1: Berechne benötigte Bits",
        [
            f"Du willst {n} Subnetze.",
            f"Frage: 2^wieviele Bits ≥ {n}?",
            f"→ Wir brauchen mindestens {n} Subnetze.",
            "Merke: Jedes Bit verdoppelt die Anzahl!",
            "2^1 = 2, 2^2 = 4, 2^3 = 8, 2^4 = 16, ...",
        ]
    )

    borrowed_bits = math.ceil(math.log2(n)) if n > 1 else 0
    new_prefix = base.prefixlen + borrowed_bits

    ui.tutor_box(
        "🧮 Schritt 2: Die Formel",
        [
            f"Formel: borrowed_bits = ceil(log2({n}))",
            f"         = ceil(log2({n})) = {borrowed_bits}",
            f"",
            f"Neues Präfix = altes Präfix + borrowed_bits",
            f"              = /{base.prefixlen} + {borrowed_bits}",
            f"              = /{new_prefix}",
        ]
    )

    ui.tutor_box(
        "🧮 Schritt 3: Was bedeutet das?",
        [
            f"Ursprünglich: /{base.prefixlen} = {32-base.prefixlen} Host-Bits",
            f"Neues Präfix: /{new_prefix} = {32-new_prefix} Host-Bits",
            f"Geborgt: {borrowed_bits} Bits für Subnetze",
            f"",
            f"Anzahl Subnetze: 2^{borrowed_bits} = {2**borrowed_bits}",
            f"Hosts pro Subnetz: 2^{32-new_prefix} - 2 = {2**(32-new_prefix)-2}",
        ]
    )

    ui.tutor_box(
        "🎯 Schritt 4: Die neue Netzmaske",
        [
            f"Alte Maske: /{base.prefixlen} → {mask_from_prefix(base.prefixlen)}",
            f"Neue Maske: /{new_prefix} → {mask_from_prefix(new_prefix)}",
            f"",
            "Erklärung:",
            f"Von den {32-base.prefixlen} Host-Bits",
            f"nehmen wir {borrowed_bits} für Subnetze",
            f"bleiben {32-new_prefix} für Hosts übrig",
        ]
    )

    mask_list = list(map(int, mask_from_prefix(new_prefix).split('.')))
    magic = 2**(8 - (new_prefix % 8)) if new_prefix % 8 != 0 else 256

    ui.tutor_box(
        "🔢 Schritt 5: Magic Number",
        [
            "Was ist die Magic Number?",
            "→ Die Sprunggröße zwischen Netzadressen",
            "",
            f"Interessantes Oktett: {new_prefix % 8 if new_prefix % 8 != 0 else 8}. Oktett",
            f"Maskenwert dort: {mask_list[new_prefix//8]}",
            f"Magic Number = 256 - {mask_list[new_prefix//8]} = {magic}",
            f"",
            f"Netzadressen: 0, +{magic}, +{magic}, +{magic}, ...",
        ]
    )

    infos = [describe_subnet(s, borrowed_bits=borrowed_bits) for s in list(base.subnets(new_prefix=new_prefix))]
    
    ui.headline(f"Ergebnis: {len(infos)} Subnetze")
    ui.info("")
    print_subnets(ui, infos, limit=16)
    
    if len(infos) > 16:
        ui.warn(f"\n(Gezeigt: 16 von {len(infos)} Subnetzen)")

    ui.tutor_box(
        "📝 Zusammenfassung - Merke dir das!",
        [
            f"✅ Ausgangsnetz: {base}",
            f"✅ Gewünschte Subnetze: {n}",
            f"✅ Geborgte Bits: {borrowed_bits}",
            f"✅ Neues Präfix: /{new_prefix}",
            f"✅ Neue Maske: {mask_from_prefix(new_prefix)}",
            f"✅ Magic Number: {2**(8 - (new_prefix % 8))}",
            f"",
            "🔑 Merksatz:",
            "'Mehr Subnetze → Präfix größer → weniger Hosts'",
        ]
    )

    if yes_no("\nNochmal üben mit anderen Werten? (j/n): "):
        action_split_by_n(ui)
    elif yes_no("Exportieren (MD+CSV)? (j/n): "):
        export_markdown_and_csv(ui, base, "by_count", infos)


def action_split_by_prefix(ui: UI) -> None:
    ui.headline("2) Netzwerk auf Ziel-Präfix aufteilen (Lerne: /xx!)")
    
    ui.tutor_box(
        "🎓 LERNEN: Was bedeutet /xx?",
        [
            "/xx ist die CIDR-Schreibweise (Classless Inter-Domain Routing)",
            "",
            "Beispiele:",
            "/24 → 255.255.255.0 → 256 Adressen (Klasse C)",
            "/25 → 255.255.255.128 → 128 Adressen",
            "/26 → 255.255.255.192 → 64 Adressen",
            "/27 → 255.255.255.224 → 32 Adressen",
            "/28 → 255.255.255.240 → 16 Adressen",
            "/30 → 255.255.255.252 → 4 Adressen (P2P)",
            "",
            "Je größer das Präfix, desto KLEINER das Netz!",
            "/24 ist GROß, /30 ist KLEIN",
        ]
    )

    base = ask_net(ui, "Ausgangsnetz (z.B. 10.0.0.0/16): ")
    if base is None:
        return
    
    ui.info(f"\n📌 Dein Netz: {base}")
    ui.info(f"   Aktuell: /{base.prefixlen} = {mask_from_prefix(base.prefixlen)}")
    
    new_prefix = ask_int(ui, "\nZiel-Präfix (z.B. 24): ", min_v=0, max_v=32)
    if new_prefix is None:
        return

    if new_prefix < base.prefixlen:
        ui.error(f"Nicht möglich: Ziel-Präfix /{new_prefix} ist kleiner als Ausgang /{base.prefixlen}.")
        return

    borrowed_bits = new_prefix - base.prefixlen
    subs = list(base.subnets(new_prefix=new_prefix))

    ui.tutor_box(
        "🧮 Schritt 1: Berechne geborgte Bits",
        [
            f"Formel: borrowed_bits = Zielpräfix - Ausgangspräfix",
            f"        = /{new_prefix} - /{base.prefixlen}",
            f"        = {borrowed_bits}",
            "",
            f"Anzahl neuer Subnetze: 2^{borrowed_bits} = {len(subs)}",
        ]
    )

    ui.tutor_box(
        "🧮 Schritt 2: Was ändert sich?",
        [
            f"Altes Präfix: /{base.prefixlen}",
            f"  → Host-Bits: {32-base.prefixlen}",
            f"  → Maske: {mask_from_prefix(base.prefixlen)}",
            "",
            f"Neues Präfix: /{new_prefix}",
            f"  → Host-Bits: {32-new_prefix}",
            f"  → Maske: {mask_from_prefix(new_prefix)}",
            "",
            f"Weniger Host-Bits: {32-base.prefixlen} - {borrowed_bits} = {32-new_prefix}",
        ]
    )

    mask_list = list(map(int, mask_from_prefix(new_prefix).split('.')))
    magic = 2**(8 - (new_prefix % 8)) if new_prefix % 8 != 0 else 256

    ui.tutor_box(
        "🧮 Schritt 3: Magic Number (Sprunggröße)",
        [
            f"Interessantes Oktett: {new_prefix//8 + 1}.",
            f"Maskenwert dort: {mask_list[new_prefix//8]}",
            f"Magic Number = 256 - {mask_list[new_prefix//8]} = {magic}",
            "",
            f"Das heißt: Netzadressen springen um {magic}",
            f"Beispiel: 0, {magic}, {magic*2}, {magic*3}, ...",
        ]
    )

    ui.tutor_box(
        "🎯 Ergebnis",
        [
            f"✅ Ausgangsnetz: {base}",
            f"✅ Ziel-Präfix: /{new_prefix}",
            f"✅ Geborgte Bits: {borrowed_bits}",
            f"✅ Neue Subnetze: {len(subs)}",
            f"✅ Hosts pro Subnetz: {2**(32-new_prefix)-2}",
            f"✅ Magic Number: {magic}",
        ]
    )

    infos = [describe_subnet(s, borrowed_bits=borrowed_bits) for s in subs]
    
    ui.headline(f"Ergebnis: {len(infos)} Subnetze")
    ui.info("")
    print_subnets(ui, infos, limit=16)
    
    if len(infos) > 16:
        ui.warn(f"\n(Gezeigt: 16 von {len(infos)} Subnetzen)")

    if yes_no("\nNochmal üben? (j/n): "):
        action_split_by_prefix(ui)
    elif yes_no("Exportieren (MD+CSV)? (j/n): "):
        export_markdown_and_csv(ui, base, "by_prefix", infos)


def action_split_by_hosts(ui: UI) -> None:
    ui.headline("3) Subnetze nach Hosts (Lerne: Wie viele Hosts brauche ich?)")
    
    ui.tutor_box(
        "🎓 LERNEN: Host-Berechnung",
        [
            "Frage: Wieviele Hosts brauchst du pro Subnetz?",
            "",
            "WICHTIG: Netzadresse + Broadcast = 2 reserviert!",
            "→ Nutzbare Hosts = Gesamt - 2",
            "",
            "Beispiele:",
            "30 Hosts brauchen → brauchst 32 Adressen → /26",
            "14 Hosts brauchen → brauchst 16 Adressen → /28",
            "6 Hosts brauchen → brauchst 8 Adressen → /29",
            "",
            "Formel: Host-Bits = ceil(log2(Host + 2))",
            "Präfix = 32 - Host-Bits",
        ]
    )

    base = ask_net(ui, "Ausgangsnetz (z.B. 172.16.0.0/20): ")
    if base is None:
        return
    
    ui.info(f"\n📌 Dein Netz: {base}")
    ui.info(f"   Maximale Hosts: {2**(32-base.prefixlen)-2}")
    
    hosts = ask_int(ui, "\nWie viele Hosts brauchst du pro Subnetz? ", min_v=1)
    if hosts is None:
        return

    host_bits = math.ceil(math.log2(hosts + 2))
    new_prefix = 32 - host_bits
    borrowed_bits = new_prefix - base.prefixlen
    subs = list(base.subnets(new_prefix=new_prefix))

    ui.tutor_box(
        "🧮 Schritt 1: Berechne benötigte Host-Bits",
        [
            f"Du brauchst: {hosts} nutzbare Hosts",
            "",
            f"Formel: host_bits = ceil(log2({hosts} + 2))",
            f"              = ceil(log2({hosts+2}))",
            f"              = {host_bits} bits",
            "",
            f"Erklärung:",
            f"→ {hosts} Hosts + 2 (Netz+Broadcast) = {hosts+2} Adressen",
            f"→ log2({hosts+2}) = {math.log2(hosts+2):.2f}",
            f"→ aufrunden = {host_bits} bits",
        ]
    )

    ui.tutor_box(
        "🧮 Schritt 2: Berechne neues Präfix",
        [
            f"Formel: Präfix = 32 - Host-Bits",
            f"        = 32 - {host_bits}",
            f"        = /{new_prefix}",
            "",
            f"Das heißt:",
            f"/{new_prefix} hat {2**(32-new_prefix)} Adressen",
            f"davon nutzbar: {2**(32-new_prefix)-2} Hosts",
        ]
    )

    if new_prefix < base.prefixlen:
        ui.error(f"\n❌ Problem: /{new_prefix} ist kleiner als /{base.prefixlen}!")
        ui.error(f"   Dein Netz ist zu klein für {hosts} Hosts.")
        ui.error(f"   Maximum in {base}: {2**(32-base.prefixlen)-2} Hosts")
        return

    ui.tutor_box(
        "🧮 Schritt 3: Geborgte Bits & Subnetze",
        [
            f"Du borgst: {borrowed_bits} Bits von den Hosts",
            f"→ von /{base.prefixlen} auf /{new_prefix}",
            "",
            f"Anzahl Subnetze: 2^{borrowed_bits} = {len(subs)}",
        ]
    )

    mask_list = list(map(int, mask_from_prefix(new_prefix).split('.')))
    magic = 2**(8 - (new_prefix % 8)) if new_prefix % 8 != 0 else 256

    ui.tutor_box(
        "🧮 Schritt 4: Die Magic Number",
        [
            f"Magic Number = 256 - {mask_list[new_prefix//8]} = {magic}",
            f"",
            f"Netzadressen: 0, +{magic}, +{magic}, +{magic}, ...",
        ]
    )

    ui.tutor_box(
        "🎯 Ergebnis",
        [
            f"✅ Ausgangsnetz: {base}",
            f"✅ Gewünschte Hosts: {hosts}",
            f"✅ Host-Bits: {host_bits}",
            f"✅ Neues Präfix: /{new_prefix}",
            f"✅ Nutzbare Hosts: {2**(32-new_prefix)-2}",
            f"✅ Neue Subnetze: {len(subs)}",
        ]
    )

    infos = [describe_subnet(s, borrowed_bits=borrowed_bits) for s in subs]
    
    ui.headline(f"Ergebnis: {len(infos)} Subnetze mit je {2**(32-new_prefix)-2} Hosts")
    ui.info("")
    print_subnets(ui, infos, limit=16)
    
    if len(infos) > 16:
        ui.warn(f"\n(Gezeigt: 16 von {len(infos)} Subnetzen)")

    if yes_no("\nNochmal üben? (j/n): "):
        action_split_by_hosts(ui)
    elif yes_no("Exportieren (MD+CSV)? (j/n): "):
        export_markdown_and_csv(ui, base, "by_hosts", infos)


def action_ip_in_subnet(ui: UI) -> None:
    ui.headline("4) IP → Subnetz (Lerne: Wo gehört eine IP hin?)")
    
    ui.tutor_box(
        "🎓 LERNEN: Wie finde ich das Subnetz?",
        [
            "Frage: Gegeben eine IP, in welchem Subnetz liegt sie?",
            "",
            "Methode:",
            "1. Nimm die IP und die Subnetz-Maske",
            "2. Mache eine UND-Operation (AND)",
            "3. Das Ergebnis = Netzwerk-Adresse",
            "",
            "Beispiel:",
            "IP: 192.168.1.130",
            "Maske: 255.255.255.224 (/27)",
            "IP AND Maske = 192.168.1.128 → Netzwerk-Adresse!",
        ]
    )

    base = ask_net(ui, "Ausgangsnetz (z.B. 192.168.1.0/24): ")
    if base is None:
        return
    
    target_prefix = ask_int(ui, "Ziel-Präfix (z.B. 27): ", min_v=0, max_v=32)
    if target_prefix is None:
        return

    if target_prefix < base.prefixlen:
        ui.error(f"Ziel-Präfix /{target_prefix} muss >= /{base.prefixlen} sein.")
        return

    ip = ask_ip(ui, "IP-Adresse (z.B. 192.168.1.130): ")
    if ip is None:
        return

    ui.tutor_box(
        "🧮 Schritt 1: Berechne Netzwerk-Adresse",
        [
            f"IP-Adresse: {ip}",
            f"Netzmaske: /{target_prefix} → {mask_from_prefix(target_prefix)}",
            "",
            "Rechnung (AND-Operation):",
            f"IP binary:      {ip_to_binary(str(ip))}",
            f"Maske binary:   {mask_to_binary(mask_from_prefix(target_prefix))}",
            "─────────────────────────",
            f"Netzwerk:       {ip_to_binary(str(ipaddress.IPv4Network(f'{ip}/{target_prefix}', strict=False).network_address))}",
        ]
    )

    subs = list(base.subnets(new_prefix=target_prefix))
    hit = next((s for s in subs if ip in s), None)

    if hit is None:
        ui.error(f"❌ IP {ip} liegt NICHT im Netz {base}!")
        return

    info = describe_subnet(hit, borrowed_bits=target_prefix - base.prefixlen)

    ui.tutor_box(
        "🧮 Schritt 2: Ergebnis",
        [
            f"✅ IP {ip} liegt in Subnetz {info.subnet}",
            f"",
            f"Netzwerk-Adresse: {info.network}",
            f"Broadcast-Adresse: {info.broadcast}",
            f"Host-Range: {info.first_host} - {info.last_host}",
            f"",
            f"Prüfung: Ist {info.network} <= {ip} <= {info.broadcast}?",
            f"→ JA! Die IP liegt in diesem Subnetz.",
        ]
    )

    ui.tutor_box(
        "🧮 Schritt 3: Magic Number Prüfung",
        [
            f"Magic Number: {info.magic_number}",
            f"Interessantes Oktett: {info.interesting_octet}.",
            "",
            f"Netzadressen in diesem Netz:",
            f"{base.network_address}, +{info.magic_number}, +{info.magic_number}, ...",
            f"",
            f"{ip} fällt in das Subnetz mit Netzwerk {info.network}",
        ]
    )

    if yes_no("\nNochmal üben? (j/n): "):
        action_ip_in_subnet(ui)


def action_analyze_network(ui: UI) -> None:
    ui.headline("5) Subnetz analysieren (Lerne: Was bedeutet /xx?)")
    
    ui.tutor_box(
        "🎓 LERNEN: Die Basics",
        [
            "Ein IPv4-Netz hat 32 Bits (4 x 8 = 32)",
            "",
            "/xx bedeutet: xx Bits sind für das Netz, der Rest für Hosts",
            "",
            "/24 → 24 Netz-Bits, 8 Host-Bits",
            "/25 → 25 Netz-Bits, 7 Host-Bits",
            "/26 → 26 Netz-Bits, 6 Host-Bits",
            "/27 → 27 Netz-Bits, 5 Host-Bits",
            "/28 → 28 Netz-Bits, 4 Host-Bits",
            "/30 → 30 Netz-Bits, 2 Host-Bits (P2P)",
            "",
            "Host-Bits = 32 - Präfix",
            "Adressen = 2^(Host-Bits)",
        ]
    )

    net = ask_net(ui, "Netzwerk (z.B. 192.168.1.0/27): ")
    if net is None:
        return

    info = describe_subnet(net)

    ui.tutor_box(
        "📊 Grunddaten",
        [
            f"Netzwerk-Adresse: {info.network} (erste Adresse)",
            f"Broadcast-Adresse: {info.broadcast} (letzte Adresse)",
            f"Host-Range: {info.first_host} - {info.last_host}",
            f"",
            f"Präfix: /{net.prefixlen}",
            f"Netzmaske: {info.netmask}",
            f"Wildcard: {info.wildcard}",
        ]
    )

    ui.tutor_box(
        "📊 Zahlen",
        [
            f"Gesamt-Adressen: {info.total_addresses}",
            f"Nutzbare Hosts: {info.usable_hosts}",
            f"Host-Bits: {info.host_bits}",
            f"Magic Number: {info.magic_number}",
        ]
    )

    ui.tutor_box(
        "🔢 Binär-Darstellung (das Wichtigste!)",
        [
            f"Netzwerk: {info.network}",
            f"  Binär:  {ip_to_binary(str(net.network_address))}",
            f"",
            f"Netzmaske: {info.netmask}",
            f"  Binär:  {mask_to_binary(info.netmask)}",
            f"",
            f"Wildcard:  {info.wildcard}",
            f"  Binär:  {mask_to_binary(info.wildcard)}",
            f"",
            "Erklärung:",
            "1 = Netz-Bit (fest)",
            "0 = Host-Bit (variabel)",
        ]
    )

    ui.tutor_box(
        "🧮 Wie berechnet man?",
        [
            f"Host-Bits = 32 - {net.prefixlen} = {info.host_bits}",
            f"Adressen = 2^{info.host_bits} = {info.total_addresses}",
            f"Nutzbar = {info.total_addresses} - 2 = {info.usable_hosts}",
            f"(Minus 2: Netzadresse + Broadcast)",
            "",
            f"Magic Number: 256 - {info.mask_octet_value} = {info.magic_number}",
            f"Sprung zwischen Netzwerken: {info.magic_number}",
        ]
    )

    print_classful_context(ui, net)
    print_tricks(ui, net.prefixlen)

    if yes_no("\nNochmal üben? (j/n): "):
        action_analyze_network(ui)


def run_action_safely(ui: UI, action: callable) -> None:
    """Fängt Rechen-/Eingabefehler pro Menüaktion ab, damit das Tool nicht abstürzt."""
    try:
        action(ui)
    except ValueError as exc:
        ui.error(f"Fehler: {exc}")
        ui.tutor_box(
            "Hinweis zur Eingabe",
            [
                "Prüfe, ob die gewünschte Aufteilung innerhalb des Ausgangsnetzes möglich ist.",
                "Tipp: Bei sehr kleinen Netzen (/30, /31, /32) sind nur wenige weitere Subnetze möglich.",
            ],
        )



def parse_args(argv: list[str]) -> bool:
    return "--no-color" not in argv


def main() -> None:
    use_color = parse_args(sys.argv[1:])
    ui = UI(use_color=use_color)

    ui.headline("IPv4 Subnetting Tutor – LPIC / IHK / CompTIA")
    ui.info("Hinweis: Farben aus = starte mit: python3 subnetear.py --no-color")
    ui.info("Tipp: Bei jeder Eingabe 'b' oder Enter für Zurück zum Menü")
    ui.info("Dieses Tool ist Rechner + Trainer + Lernhilfe.\n")

    while True:
        ui.info(ui.c("Menü:", ui.H))
        ui.info("  1) Netzwerk in N Subnetze aufteilen (IPv4)")
        ui.info("  2) Netzwerk auf Ziel-Präfix /xx aufteilen (IPv4)")
        ui.info("  3) Subnetze nach Hosts/Subnetz (IPv4)")
        ui.info("  4) IP -> Subnetz (IPv4)")
        ui.info("  5) Subnetz analysieren (IPv4)")
        ui.info("  6) IPv6 Subnetz analysieren")
        ui.info("  7) IPv6 Netz aufteilen")
        ui.info("  8) Quiz: Teste dein Wissen")
        ui.info("  9) VLSM: Variable Length Subnet Mask")
        ui.info("  0) Beenden")

        try:
            choice = input("\nAuswahl: ").strip()
        except (EOFError, KeyboardInterrupt):
            ui.success("\nBis dann!")
            return

        if choice == "1":
            run_action_safely(ui, action_split_by_n)
        elif choice == "2":
            run_action_safely(ui, action_split_by_prefix)
        elif choice == "3":
            run_action_safely(ui, action_split_by_hosts)
        elif choice == "4":
            run_action_safely(ui, action_ip_in_subnet)
        elif choice == "5":
            run_action_safely(ui, action_analyze_network)
        elif choice == "6":
            run_action_safely(ui, action_ipv6_analyze)
        elif choice == "7":
            run_action_safely(ui, action_ipv6_subnet)
        elif choice == "8":
            run_action_safely(ui, action_quiz)
        elif choice == "9":
            run_action_safely(ui, action_vlsm)
        elif choice == "0":
            ui.success("Bis dann. Sauber subnetten. 🧠")
            return
        else:
            ui.error("Ungültige Auswahl. Bitte 0–9.")

        print("")


if __name__ == "__main__":
    main()
