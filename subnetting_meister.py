#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
subnetting_meister.py – Dein Subnetting-Trainer für die Systemintegration (Stand 2026)

WAS KANN DAS TOOL?
  1  IP-Analyse         : Netz, Broadcast, Hosts – Schritt für Schritt MIT Binärdarstellung
  2  Teilen nach Anzahl : "Teile mein Netz in N Subnetze"
  3  Teilen nach Präfix : "Teile mein Netz in lauter /27"
  4  VLSM               : Subnetze unterschiedlicher Größe (das Praxis-Werkzeug!)
  5  Gleiches Netz?     : Können zwei Hosts ohne Router miteinander reden?
  6  Spickzettel        : Tabellen, private/spezielle Bereiche, Praxis-Tipps, typische Fehler
  7  Quiz               : Prüfungstraining (AP1-Stil) mit Hinweisen
  8  IPv6               : Grundlagen, Adressanalyse, /48 -> /64 teilen
  9  Speichern          : Alles aus der Sitzung als .md (Notizen) und .csv (Tabelle)
 10  Python-Lernecke    : Der Code dieses Tools, erklärt – mit echten Beispielwerten

START MIT MENÜ:   subnetear            (oder: python3 subnetting_meister.py)

DIREKT AUS DEM TERMINAL (ohne Menü):
  subnetear 192.168.10.77/26                   Schnellanalyse (Schritt für Schritt)
  subnetear 10.0.0.0/24 /27                    Netz in lauter /27 teilen
  subnetear 10.0.0.0/24 -n 4                   Netz in 4 Subnetze teilen
  subnetear 192.168.0.0/24 --vlsm 100,50,20,2  VLSM mit verschieden großen Subnetzen
  subnetear 2001:db8:abcd::/48 /64             IPv6: /48 in /64 teilen
  subnetear 2001:db8:abcd:12::1/64             IPv6: Adresse analysieren
  subnetear --python                           Python-Lernecke
  subnetear --hilfe                            Hilfe mit allen Optionen

OHNE ANIMATION (z. B. zum Kopieren/Testen):   subnetear --ohne-animation

AUTOMATISCHE ANPASSUNG AN JEDEN BILDSCHIRM (Handy, Tablet, Laptop, SSH ...):
  Bei JEDER Ausgabe misst das Tool die aktuelle Terminalbreite. Lange Texte werden sauber
  umbrochen, Tabellen werden auf schmalen Bildschirmen zu übersichtlichen "Karten",
  Binärzahlen bekommen eine eigene Zeile. Du musst nichts einstellen.
  Zum Ausprobieren:   COLUMNS=40 subnetear 10.0.0.0/24 -n 4

PYTHON-GRUNDLAGEN, DIE DU HIER SIEHST (zum Mitlernen):
  def name():     definiert eine Funktion (ein wiederverwendbarer Baustein)
  input()         liest Text von der Tastatur
  if / elif / else  Entscheidungen
  for x in liste: wiederholt etwas für jedes Element
  try / except    fängt Fehler ab, damit das Programm nicht abstürzt
  f"Text {x}"     f-String: setzt den Wert von x in den Text ein
  return          gibt ein Ergebnis aus einer Funktion zurück
"""

import argparse                 # liest die Argumente aus der Kommandozeile (subnetear 10.0.0.0/24 -n 4)
import csv                      # CSV-Dateien schreiben (für LibreOffice/Excel)
import ipaddress               # Standardbibliothek für IP-Adressen und Netze (sehr mächtig)
import math                     # log2, ceil ... für die Hostbit-Rechnung
import os                       # Umgebungsvariablen, Betriebssystem-Infos
import random                   # Zufallsfragen für das Quiz
import re                       # reguläre Ausdrücke (hier: Farbcodes entfernen)
import shutil                   # Terminalbreite ermitteln
import sys                      # Argumente, Ausgabe-Steuerung
import time                     # kleine Pausen für die Animation
import unicodedata              # Zeichenbreite (Emojis sind im Terminal 2 Spalten breit)
from datetime import datetime   # Zeitstempel für Dateinamen
from itertools import islice    # nur die ersten N Elemente aus einer riesigen Liste holen
from pathlib import Path        # Dateipfade plattformunabhängig


# =============================================================================
# 1. TERMINAL-HELFER: Farben, Animation, Protokoll, automatische Breite
# =============================================================================

# Farben nur, wenn wir in einem echten Terminal sind (nicht bei Umleitung in eine Datei)
FARBEN_AN = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
ANIM_AN = sys.stdout.isatty() and "--ohne-animation" not in sys.argv

if FARBEN_AN and os.name == "nt":
    os.system("")  # schaltet ANSI-Farben in älteren Windows-Terminals ein


class F:
    """Farbcodes (ANSI). Ein 'class' hier ist nur eine Ablage für Konstanten."""
    RESET = "\033[0m"
    FETT = "\033[1m"
    DIM = "\033[2m"
    ROT = "\033[91m"
    GRUEN = "\033[92m"
    GELB = "\033[93m"
    BLAU = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    GRAU = "\033[90m"


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")   # Muster, das Farbcodes erkennt
PROTOKOLL: list[str] = []                 # alles, was berechnet wurde -> für den Export
TABELLE: list[dict] = []                  # Tabellenzeilen -> für den CSV-Export


# ---------- Automatische Anpassung an die Bildschirmbreite -------------------
# Idee: Wir fragen BEI JEDER AUSGABE neu, wie breit das Terminal gerade ist.
# So passt sich das Tool an, auch wenn du das Handy drehst oder das Fenster änderst.

def terminal_breite() -> int:
    """Spalten des Terminals. Bei Umleitung in eine Datei: 100. COLUMNS=40 überschreibt (zum Testen)."""
    return shutil.get_terminal_size((100, 24)).columns


def zeilenbreite() -> int:
    """Nutzbare Zeichen pro Zeile. Eine Spalte bleibt frei, damit das Terminal nicht selbst umbricht."""
    return max(30, terminal_breite() - 1)


def breite() -> int:
    """Breite für Rahmen und Linien (nie breiter als 78, damit es auf großen Monitoren hübsch bleibt)."""
    return max(30, min(terminal_breite() - 1, 78))


def passt(n: int) -> bool:
    """Passt etwas, das n Zeichen breit ist, auf den Bildschirm? Damit wählen wir Tabelle oder Karte."""
    return zeilenbreite() >= n


def sichtbare_laenge(text: str) -> int:
    """
    Wie viele Spalten belegt der Text im Terminal wirklich?
    - Farbcodes sind unsichtbar (0 Spalten)
    - Emojis und CJK-Zeichen belegen 2 Spalten
    - Kombinierende Zeichen (z. B. das Emoji-Variantenzeichen) belegen 0 Spalten
    """
    summe = 0
    for zeichen in ANSI_RE.sub("", text):
        if unicodedata.category(zeichen) in ("Mn", "Me", "Cf"):
            continue
        summe += 2 if unicodedata.east_asian_width(zeichen) in ("W", "F") else 1
    return summe


def umbrechen(text: str, w: int, folge: int | None = None) -> list[str]:
    """
    Bricht eine (evtl. farbige) Zeile an Leerzeichen auf Breite w um.
    folge = Einrückung der Folgezeilen (hängender Einzug). Ohne Angabe: Einzug der ersten Zeile + 2.
    Farben werden am Zeilenende beendet und in der nächsten Zeile wieder aufgenommen.
    """
    if sichtbare_laenge(text) <= w:
        return [text]
    sichtbar = ANSI_RE.sub("", text)
    if folge is None:
        folge = len(sichtbar) - len(sichtbar.lstrip(" ")) + 2
    folge = max(1, min(folge, w // 2))

    zeilen: list[str] = []
    aktiv: list[str] = []        # gerade eingeschaltete Farben
    akt: list[str] = []          # Wörter der aktuellen Zeile
    neu = False                  # True direkt nach einem Umbruch (Leerwörter überspringen)
    for wort in text.split(" "):
        hat_inhalt = bool(ANSI_RE.sub("", " ".join(akt)).strip())
        if akt and hat_inhalt and sichtbare_laenge(" ".join(akt + [wort])) > w:
            zeile = " ".join(akt).rstrip(" ")
            aktiv = []                       # Zeile beginnt schon mit den aktiven Farben -> von vorn zählen
            for treffer in ANSI_RE.finditer(zeile):
                if treffer.group(0) == F.RESET:
                    aktiv = []
                else:
                    aktiv.append(treffer.group(0))
            if aktiv:
                zeile += F.RESET
            zeilen.append(zeile)
            akt = [""] * folge
            akt[0] = "".join(aktiv)
            neu = True
        if neu and wort == "":
            continue
        akt.append(wort)
        neu = False
    zeilen.append(" ".join(akt).rstrip(" "))
    return zeilen


def c(text, *codes) -> str:
    """Färbt einen Text ein. Ohne Terminal-Farben kommt der Text unverändert zurück."""
    if not FARBEN_AN:
        return str(text)
    return "".join(codes) + str(text) + F.RESET


def drucke(text: str = "", folge: int | None = None) -> None:
    """Druckt eine Zeile und bricht sie bei Bedarf passend zur Bildschirmbreite um."""
    for zeile in umbrechen(text, zeilenbreite(), folge):
        print(zeile)


def ausgabe(text: str = "", folge: int | None = None) -> None:
    """Druckt eine Zeile (angepasst an den Bildschirm) UND merkt sich das Original (ohne Farben) für den Export."""
    drucke(text, folge)
    PROTOKOLL.append(ANSI_RE.sub("", text))


def pause(sekunden: float) -> None:
    if ANIM_AN:
        time.sleep(sekunden)


def tippe(text: str, tempo: float = 0.006, folge: int | None = None) -> None:
    """Schreibmaschinen-Effekt. Ohne Animation wird sofort gedruckt."""
    for zeile in umbrechen(text, zeilenbreite(), folge):
        if ANIM_AN:
            for zeichen in zeile:
                sys.stdout.write(zeichen)
                sys.stdout.flush()
                time.sleep(tempo)
            sys.stdout.write("\n")
        else:
            print(zeile)
    PROTOKOLL.append(ANSI_RE.sub("", text))


def regenbogen(text: str) -> str:
    """Jeder Buchstabe bekommt eine andere Farbe."""
    palette = [F.ROT, F.GELB, F.GRUEN, F.CYAN, F.BLAU, F.MAGENTA]
    return "".join(c(ch, F.FETT, palette[i % len(palette)]) if ch != " " else " "
                   for i, ch in enumerate(text))


def bitregen(zeilen: int = 9) -> None:
    """Kleine 'Matrix'-Animation aus Nullen und Einsen – Netzwerke sind am Ende nur Bits."""
    if not ANIM_AN:
        return
    for _ in range(zeilen):
        zeile = "".join(random.choice("01 ") for _ in range(breite()))
        print(c(zeile, F.GRUEN, F.DIM))
        time.sleep(0.05)


def ladebalken(text: str, schritte: int = 24) -> None:
    if not ANIM_AN:
        return
    schritte = max(5, min(schritte, zeilenbreite() - len(text) - 6))   # auf schmalen Bildschirmen kürzer
    for i in range(schritte + 1):
        balken = "█" * i + "░" * (schritte - i)
        sys.stdout.write("\r" + c(f"{text} [{balken}]", F.CYAN))
        sys.stdout.flush()
        time.sleep(0.02)
    sys.stdout.write("\r" + " " * (len(text) + schritte + 6) + "\r")


def kasten(titel: str) -> None:
    """Rahmen mit Titel – so erkennt man sofort, in welchem Modus man ist. Lange Titel werden umbrochen."""
    w = breite()
    ausgabe("")
    ausgabe(c("╔" + "═" * (w - 2) + "╗", F.CYAN))
    for teil in umbrechen(titel, w - 4, 1):
        ausgabe(c("║", F.CYAN) + c(teil.strip().center(w - 2), F.FETT, F.GELB) + c("║", F.CYAN))
    ausgabe(c("╚" + "═" * (w - 2) + "╝", F.CYAN))


def abschnitt(titel: str) -> None:
    ausgabe("")
    rest = max(3, min(breite(), 66) - len(titel) - 4)
    ausgabe(c(f"━━ {titel} ", F.FETT, F.GELB) + c("━" * rest, F.GELB))


def label_einzug() -> int:
    """Einrückung der Folgezeilen bei 'Warum/Wie/Wozu': breit = unter dem Text, schmal = kleiner Einzug."""
    return 13 if breite() >= 56 else 5


def erklaere(warum: str = "", wie: str = "", wozu: str = "") -> None:
    """Die drei Lernfragen: WARUM ist das so? WIE rechnet man? WOZU brauche ich das?"""
    if warum:
        ausgabe(c("  ❓ Warum:  ", F.BLAU, F.FETT) + warum, folge=label_einzug())
    if wie:
        ausgabe(c("  🔧 Wie:    ", F.GRUEN, F.FETT) + wie, folge=label_einzug())
    if wozu:
        ausgabe(c("  🎯 Wozu:   ", F.MAGENTA, F.FETT) + wozu, folge=label_einzug())


def tipp(text: str) -> None:
    ausgabe(c("  💡 Tipp:   ", F.GELB, F.FETT) + text, folge=label_einzug())


def achtung(text: str) -> None:
    ausgabe(c("  ⚠️  Achtung: ", F.ROT, F.FETT) + text, folge=label_einzug() + 1)


def ok(text: str) -> None:
    ausgabe(c("  ✔ ", F.GRUEN, F.FETT) + text, folge=4)


class EingabeFehler(Exception):
    """Eigene Fehlerklasse: freundliche Meldung statt kryptischem Python-Traceback."""


# VORGABEN = fertige Antworten aus der Kommandozeile. Ist die Liste gefüllt, beantwortet
# frage() die Fragen daraus, statt zu warten. So nutzen Menü UND Terminal-Befehle
# denselben Rechencode (kein doppelter Code = weniger Fehler).
VORGABEN: list[str] = []


def frage(text: str, standard: str = "") -> str:
    """Fragt den Benutzer. Leere Eingabe = Standardwert (damit man nicht tippen muss)."""
    zusatz = f" [{standard}]" if standard else ""
    if VORGABEN:                                    # Antwort kommt aus dem Terminal-Befehl
        antwort = VORGABEN.pop(0)                   # pop(0) nimmt das ERSTE Element und entfernt es
        drucke(c("➤ ", F.GRUEN, F.FETT) + text + zusatz + ": " + c(antwort, F.FETT), 2)
        return antwort or standard
    # Die Frage wird passend zur Bildschirmbreite umbrochen; nur die LETZTE Zeile ist der echte Eingabe-Prompt.
    zeilen = umbrechen(c("➤ ", F.GRUEN, F.FETT) + text + zusatz + ":", zeilenbreite() - 1, 2)
    for zeile in zeilen[:-1]:
        print(zeile)
    antwort = input(zeilen[-1].rstrip(" ") + " ").strip()
    return antwort or standard


# =============================================================================
# 2. RECHEN-BAUSTEINE (reine Mathematik, keine Ausgabe)
# =============================================================================

def lies_interface(text: str) -> ipaddress.IPv4Interface:
    """
    Liest 'IP/Präfix' ein. Erlaubt sind '192.168.10.77/26' UND '192.168.10.77/255.255.255.192'.
    Ohne Präfix nimmt Python /32 an (ein einzelner Host).
    """
    try:
        iface = ipaddress.ip_interface(text.strip())
    except ValueError:
        raise EingabeFehler("Das ist keine gültige IPv4-Adresse. Beispiel: 192.168.10.77/26")
    if iface.version != 4:
        raise EingabeFehler("Hier geht es um IPv4. Für IPv6 nimm Menüpunkt 8.")
    return iface


def lies_netz(text: str) -> ipaddress.IPv4Network:
    """
    Liest ein Netz ein. strict=False bedeutet: Hostbits dürfen gesetzt sein.
    Aus 192.168.10.77/26 wird dann automatisch das Netz 192.168.10.64/26.
    """
    try:
        netz = ipaddress.ip_network(text.strip(), strict=False)
    except ValueError:
        raise EingabeFehler("Das ist kein gültiges Netz. Beispiel: 192.168.178.0/24")
    if netz.version != 4:
        raise EingabeFehler("Hier geht es um IPv4. Für IPv6 nimm Menüpunkt 8.")
    return netz


def maske_aus_praefix(praefix: int) -> str:
    """/27 -> 255.255.255.224"""
    return str(ipaddress.IPv4Network(f"0.0.0.0/{praefix}").netmask)


def wildcard_aus_maske(maske: ipaddress.IPv4Address) -> str:
    """Wildcard = Gegenteil der Maske (jedes Bit umgedreht). 255.255.255.0 -> 0.0.0.255"""
    return str(ipaddress.IPv4Address(int(maske) ^ 0xFFFFFFFF))


def hostbits_fuer(hosts: int) -> int:
    """
    Wie viele Hostbits brauche ich für 'hosts' nutzbare Adressen?
    Wir brauchen hosts + 2 Adressen (Netzadresse + Broadcast gehen ab).
    Kleinste Zweierpotenz >= hosts + 2  ->  log2 aufrunden.
    """
    return max(2, math.ceil(math.log2(hosts + 2)))


def beschreibe(netz: ipaddress.IPv4Network) -> dict:
    """
    Alle wichtigen Daten eines Netzes in einem Dictionary (Schlüssel -> Wert).

    Sonderfälle, die das alte Skript nicht kannte:
      /31 (RFC 3021): Punkt-zu-Punkt, beide Adressen nutzbar, KEIN Broadcast
      /32           : genau ein Host (Loopback, Hostroute)
    """
    p = netz.prefixlen
    gesamt = netz.num_addresses
    if p <= 30:
        erster = netz.network_address + 1
        letzter = netz.broadcast_address - 1
        nutzbar = gesamt - 2
        broadcast = str(netz.broadcast_address)
    elif p == 31:
        erster, letzter, nutzbar = netz.network_address, netz.broadcast_address, 2
        broadcast = "-"
    else:  # /32
        erster = letzter = netz.network_address
        nutzbar = 1
        broadcast = "-"
    return {
        "netz": str(netz),
        "praefix": p,
        "maske": str(netz.netmask),
        "wildcard": wildcard_aus_maske(netz.netmask),
        "adressen": gesamt,
        "netzadresse": str(netz.network_address),
        "erster_host": str(erster),
        "letzter_host": str(letzter),
        "broadcast": broadcast,
        "nutzbare_hosts": nutzbar,
    }


def merkzahl(praefix: int) -> tuple[int, int, int]:
    """
    Die 'interessante' Stelle für das Kopfrechnen:
      Oktett-Index (0..3), Wert des Masken-Oktetts, Schrittweite (= 256 - Maskenwert).
    Beispiel /26: Maske 255.255.255.192 -> 4. Oktett, Schrittweite 256-192 = 64.
    """
    idx = min(praefix // 8, 3)
    rest = praefix - 8 * idx if praefix < 32 else 8
    maskenwert = (256 - 2 ** (8 - rest)) if rest > 0 else 0
    return idx, maskenwert, 256 - maskenwert


# Bekannte Bereiche. Der spezifischste (längste Präfix) gewinnt.
V4_BEREICHE = [
    ("0.0.0.0/8", "'Dieses Netz' (reserviert)", "nur als Quelladresse beim DHCP-Start (0.0.0.0) sinnvoll"),
    ("10.0.0.0/8", "Privat (RFC 1918)", "nicht im Internet routbar – Großes Firmennetz, 16,7 Mio. Adressen"),
    ("100.64.0.0/10", "CGNAT / Shared Address Space (RFC 6598)", "Provider-NAT; typisch bei DS-Lite/Mobilfunk – NICHT als Heimnetz wählen (VPN-Konflikte!)"),
    ("127.0.0.0/8", "Loopback", "der eigene Rechner (localhost) – verlässt nie die Netzwerkkarte"),
    ("169.254.0.0/16", "Link-Local / APIPA", "Selbstvergabe, wenn kein DHCP antwortet -> Hinweis auf DHCP-Problem!"),
    ("172.16.0.0/12", "Privat (RFC 1918)", "172.16.0.0 – 172.31.255.255; mittelgroße Netze"),
    ("192.0.0.0/24", "IETF-Protokollzuweisungen", "reserviert für Protokoll-Zwecke"),
    ("192.0.2.0/24", "Dokumentation (TEST-NET-1)", "für Beispiele in Handbüchern – nie echt verwenden"),
    ("192.168.0.0/16", "Privat (RFC 1918)", "typisches Heim-/Kleinnetz (z. B. Fritz!Box 192.168.178.0/24)"),
    ("198.18.0.0/15", "Benchmark-Tests (RFC 2544)", "für Performance-Messungen von Netzgeräten"),
    ("198.51.100.0/24", "Dokumentation (TEST-NET-2)", "für Beispiele"),
    ("203.0.113.0/24", "Dokumentation (TEST-NET-3)", "für Beispiele"),
    ("224.0.0.0/4", "Multicast", "Gruppenadresse (z. B. 224.0.0.5 = OSPF) – nie Absender-Adresse eines Hosts"),
    ("240.0.0.0/4", "Reserviert (ehem. Klasse E)", "nicht für normale Verwendung"),
    ("255.255.255.255/32", "Limited Broadcast", "geht an alle im eigenen Segment, wird vom Router nicht weitergeleitet"),
]


def klassifiziere_v4(adr: ipaddress.IPv4Address) -> tuple[str, str]:
    beste = None
    for cidr, name, hinweis in V4_BEREICHE:
        netz = ipaddress.ip_network(cidr)
        if adr in netz and (beste is None or netz.prefixlen > beste[0].prefixlen):
            beste = (netz, name, hinweis)
    if beste:
        return beste[1], beste[2]
    return "Öffentliche Adresse (Global Unicast)", "im Internet routbar – gehört einem Provider/Unternehmen"


def klasse_v4(adr: ipaddress.IPv4Address) -> str:
    """Die alte 'klassenbasierte' Einteilung. Heute ersetzt durch CIDR (1993), aber oft noch in Prüfungen."""
    erstes = int(adr) >> 24
    if erstes < 128:
        return "A (0–127, Standardmaske /8)"
    if erstes < 192:
        return "B (128–191, Standardmaske /16)"
    if erstes < 224:
        return "C (192–223, Standardmaske /24)"
    if erstes < 240:
        return "D (224–239, Multicast)"
    return "E (240–255, reserviert)"


PRAXIS = {
    8: "Riesig (16,7 Mio. Adressen). Nur als Aggregat/Adressplan, nie als ein einziges LAN (Broadcast-Domäne!).",
    16: "Sehr groß für ein Segment. Eher ein Block pro Standort, z. B. 10.20.0.0/16 für 'Standort Berlin'.",
    22: "1022 Hosts – größere Büro-/WLAN-Netze, wenn man ein VLAN bewusst groß hält.",
    23: "510 Hosts – zwei zusammengelegte /24.",
    24: "Der Klassiker fürs LAN: 254 Hosts, glatte Oktettgrenze, leicht lesbar und dokumentierbar.",
    25: "126 Hosts – halbes /24, z. B. Clients vs. Server getrennt.",
    26: "62 Hosts – viertel /24, gut für Abteilungs-VLANs.",
    27: "30 Hosts – kleine VLANs (Drucker, Telefonie, Gäste-WLAN).",
    28: "14 Hosts – kleine Server- oder DMZ-Segmente.",
    29: "6 Hosts – Management-Netze, kleine DMZ, Firewall-Cluster-Segmente.",
    30: "2 Hosts – klassischer Punkt-zu-Punkt-Link (Router zu Router).",
    31: "2 Adressen ohne Broadcast (RFC 3021) – moderner Punkt-zu-Punkt-Link, spart Adressen.",
    32: "Einzelne Adresse: Loopback/Router-ID, Hostroute oder Firewall-Regel auf genau einen Host.",
}


# =============================================================================
# 3. DARSTELLUNG: Binär, Tabellen, Karten
# =============================================================================

def binaer_farbig(wert: int, praefix: int) -> str:
    """
    32 Bits in 4 Oktetten. CYAN = Netzanteil (vorne), MAGENTA = Hostanteil (hinten).
    Genau diese Trennlinie bestimmt der Präfix!
    """
    bits = f"{wert:032b}"
    teile = []
    for i, bit in enumerate(bits):
        if i and i % 8 == 0:
            teile.append(".")
        teile.append(c(bit, F.CYAN) if i < praefix else c(bit, F.MAGENTA))
    return "".join(teile)


def binaer_block(label: str, wert: int, praefix: int, zusatz: str = "") -> None:
    """
    Eine Binärzeile 'Label  Bits  Zusatz'. Breiter Bildschirm: alles in einer Zeile.
    Schmaler Bildschirm (Handy): erst Label + Zusatz, die 35 Zeichen Bits in einer eigenen Zeile.
    """
    if passt(68):
        ausgabe(f"  {label:<11}{binaer_farbig(wert, praefix)}   {zusatz}".rstrip())
    else:
        ausgabe(f"  {label} {zusatz}".rstrip())
        ausgabe("  " + binaer_farbig(wert, praefix))


def legende() -> None:
    ausgabe("  " + c("■ Netzanteil", F.CYAN) + "   " + c("■ Hostanteil", F.MAGENTA)
            + c("   (die Grenze zwischen beiden = der Präfix)", F.GRAU))


def tabellenzeile(nr: int, d: dict) -> str:
    return (f" {nr:>3}  {d['netz']:<18} {d['erster_host']:<15} {d['letzter_host']:<15} "
            f"{d['broadcast']:<15} {d['nutzbare_hosts']:>7}")


def tabellenkopf() -> None:
    ausgabe(c("  Nr  Netz               Erster Host     Letzter Host    Broadcast       Hosts", F.FETT))
    ausgabe(c("  " + "─" * 76, F.GRAU))


def karte(nr, d: dict, bedarf: int | None = None, frei: int | None = None) -> None:
    """Ein Subnetz als kleine 'Karte' (3 Zeilen) – ideal für schmale Bildschirme."""
    kopf = c(f"  {nr:>3}  ", F.GRAU) + c(d["netz"], F.FETT, F.GRUEN)
    if bedarf is not None:
        kopf += c(f"   (Bedarf {bedarf})", F.GRAU)
    ausgabe(kopf)
    ausgabe(f"       Hosts: {d['erster_host']} – {d['letzter_host']}")
    zeile = f"       Broadcast: {d['broadcast']} · {d['nutzbare_hosts']} nutzbar"
    if frei is not None:
        zeile += f" · frei: {frei}"
    ausgabe(zeile)


def zeige_subnetze(netz_alt: ipaddress.IPv4Network, subnetze: list, max_zeilen: int = 32) -> None:
    """Gemeinsame Anzeige für 'Teilen nach Anzahl' und 'Teilen nach Präfix'."""
    abschnitt("Ergebnis-Tabelle")
    breit = passt(80)                       # Tabelle nur, wenn sie wirklich auf den Bildschirm passt
    if not breit:
        max_zeilen = min(max_zeilen, 16)    # Karten brauchen mehr Zeilen
    if breit:
        tabellenkopf()
    for nr, s in enumerate(subnetze, 1):
        d = beschreibe(s)
        TABELLE.append({"nr": nr, **d})
        if nr <= max_zeilen:
            if breit:
                ausgabe(tabellenzeile(nr, d))
            else:
                karte(nr, d)
    if len(subnetze) > max_zeilen:
        ausgabe(c(f"  … und {len(subnetze) - max_zeilen} weitere (komplett im CSV-Export, Menüpunkt 9)", F.GRAU))

    erstes = subnetze[0]
    abschnitt("Merkzahl-Methode am ersten Subnetz")
    idx, maskenwert, schritt = merkzahl(erstes.prefixlen)
    erklaere(
        warum=f"Die Subnetze liegen immer in gleichen Abständen. Der Abstand = Blockgröße = {schritt} "
              f"im {idx + 1}. Oktett (256 - {maskenwert}).",
        wie=f"Netze starten bei 0, {schritt}, {2 * schritt}, {3 * schritt} … im {idx + 1}. Oktett. "
            f"Broadcast = nächstes Netz - 1.",
        wozu="So findest du im Kopf (ohne Binär!) das richtige Netz – wichtig in jeder Prüfung.",
    )


# =============================================================================
# 4. MODI
# =============================================================================

# ---------- Modus 1: IP-Analyse ----------------------------------------------

def modus_analyse() -> None:
    kasten("1 · IP-ANALYSE  –  alles zu einer Adresse, Schritt für Schritt")
    erklaere(wozu="Im Alltag: 'In welchem Netz sitzt dieser Host? Ist das Gateway im selben Netz? "
                  "Wie viele Adressen habe ich noch?'")
    eingabe = frage("IP mit Präfix (z. B. 192.168.10.77/26)", "192.168.10.77/26")
    iface = lies_interface(eingabe)
    ip, netz = iface.ip, iface.network
    p = netz.prefixlen
    d = beschreibe(netz)
    ladebalken("Rechne")

    # --- Schritt 1: Präfix -> Maske
    abschnitt("Schritt 1 · Präfix = Anzahl der Netz-Bits")
    tippe(f"  /{p} bedeutet: die ersten {p} von 32 Bits gehören zum NETZ, die restlichen {32 - p} zum HOST.")
    binaer_block("Maske:", int(netz.netmask), p)
    ausgabe(f"  Maske dezimal: {c(d['maske'], F.FETT)}")
    legende()
    erklaere(
        warum="Die Maske ist ein 'Stempel': Einsen = Netzanteil, Nullen = Hostanteil.",
        wie=f"{p} Einsen von links, Rest Nullen, dann in 4 Oktette à 8 Bit zerlegen und umrechnen.",
        wozu="Die Maske sagt jedem Gerät, welche Adressen 'nebenan' (ohne Router) erreichbar sind.",
    )
    tipp("Maskenoktett-Werte auswendig: 128 · 192 · 224 · 240 · 248 · 252 · 254 · 255 "
         "(1, 2, 3 … 8 Einsen im Oktett).")

    # --- Schritt 2: Hostbits -> Blockgröße
    abschnitt("Schritt 2 · Hostbits und Blockgröße")
    h = 32 - p
    ausgabe(f"  Hostbits = 32 - {p} = {c(h, F.FETT)}")
    ausgabe(f"  Adressen im Netz = 2^{h} = {c(d['adressen'], F.FETT)}")
    if p <= 30:
        ausgabe(f"  Nutzbare Hosts   = 2^{h} - 2 = {c(d['nutzbare_hosts'], F.FETT, F.GRUEN)}")
    elif p == 31:
        ausgabe(f"  Nutzbare Hosts   = 2 (Sonderfall /31, RFC 3021: kein Netz-/Broadcast-Abzug)")
    else:
        ausgabe("  Nutzbare Hosts   = 1 (Sonderfall /32: genau eine Adresse)")
    erklaere(
        warum="Jedes Hostbit verdoppelt die Adressanzahl (0 oder 1). Von allen Adressen sind zwei "
              "reserviert: die erste = Netzadresse, die letzte = Broadcast.",
        wie="2 hoch Hostbits, dann minus 2.",
        wozu="Zu klein geplant = später umbauen. Zu groß = Adressen und Broadcast-Domäne verschwendet.",
    )

    # --- Schritt 3: Netzadresse per UND
    abschnitt("Schritt 3 · Netzadresse = IP UND Maske")
    binaer_block("IP:", int(ip), p, str(ip))
    binaer_block("Maske:", int(netz.netmask), p, d["maske"])
    if passt(90):
        ausgabe(c("             " + "─" * 35, F.GRAU) + "  (bitweises UND: 1 UND 1 = 1, sonst 0)")
    else:
        ausgabe(c("  " + "─" * 35, F.GRAU))
        ausgabe(c("  (bitweises UND: 1 UND 1 = 1, sonst 0)", F.GRAU))
    binaer_block("Netz:", int(netz.network_address), p, c(d["netzadresse"], F.FETT, F.GRUEN))
    erklaere(
        warum="UND mit der Maske 'löscht' den Hostanteil – übrig bleibt die Adresse des Netzes selbst.",
        wozu="Zwei Hosts sind im selben Netz, wenn ihre Netzadressen gleich sind (siehe Menüpunkt 5).",
    )

    # --- Schritt 4: Broadcast per ODER
    abschnitt("Schritt 4 · Broadcast = alle Hostbits auf 1")
    ausgabe(f"  Wildcard:  {d['wildcard']}  (Maske umgedreht)")
    if p <= 30:
        binaer_block("Broadcast:", int(netz.broadcast_address), p, c(d["broadcast"], F.FETT, F.GRUEN))
    else:
        ausgabe(f"  Bei /{p} gibt es keinen klassischen Broadcast.")
    erklaere(
        warum="Der Broadcast ist die 'Rundruf-Adresse': ein Paket daran erreicht ALLE Hosts im Netz.",
        wozu="Er darf keinem Gerät fest zugewiesen werden. Auch die Wildcard nutzt du später bei ACLs/OSPF.",
    )

    # --- Schritt 5: Hostbereich
    abschnitt("Schritt 5 · Hostbereich")
    ausgabe(f"  Erster Host:  {c(d['erster_host'], F.FETT)}")
    ausgabe(f"  Letzter Host: {c(d['letzter_host'], F.FETT)}")
    if p <= 30 and ip == netz.network_address:
        achtung("Deine IP ist die NETZADRESSE – so kannst du sie keinem Host geben!")
    if p <= 30 and ip == netz.broadcast_address:
        achtung("Deine IP ist die BROADCAST-Adresse – so kannst du sie keinem Host geben!")

    # --- Schritt 6: Merkzahl
    abschnitt("Schritt 6 · Kopfrechnen mit der Merkzahl (ohne Binär)")
    idx, maskenwert, schritt = merkzahl(p)
    oktett = int(str(ip).split(".")[idx])
    netzoktett = (oktett // schritt) * schritt if schritt <= 256 else 0
    ausgabe(f"  Interessantes Oktett: das {idx + 1}.  (Maskenwert {maskenwert})")
    ausgabe(f"  Schrittweite = 256 - {maskenwert} = {c(schritt, F.FETT)}")
    ausgabe(f"  Netz-Oktett  = ({oktett} ÷ {schritt}, abgerundet) × {schritt} = {c(netzoktett, F.FETT)}")
    ausgabe(f"  Broadcast-Oktett = {netzoktett} + {schritt} - 1 = {netzoktett + schritt - 1}")
    tipp("Das ist der schnellste Weg in der Prüfung: eine Division, eine Multiplikation, fertig.")

    # --- Schritt 7: Typ
    abschnitt("Schritt 7 · Was für eine Adresse ist das?")
    typ, hinweis = klassifiziere_v4(ip)
    ausgabe(f"  Typ:    {c(typ, F.FETT)}", folge=10)
    ausgabe(f"  Info:   {hinweis}", folge=10)
    ausgabe(f"  Klasse: {klasse_v4(ip)}  {c('(historisch – heute zählt nur der Präfix, CIDR)', F.GRAU)}", folge=10)
    if p in PRAXIS:
        tipp(f"/{p} in der Praxis: {PRAXIS[p]}")
    TABELLE.append({"nr": "", **d})


# ---------- Modus 2: Teilen nach Anzahl --------------------------------------

def modus_teilen_anzahl() -> None:
    kasten("2 · NETZ TEILEN NACH ANZAHL  –  'Ich brauche N Subnetze'")
    erklaere(wozu="Du hast ein Netz (z. B. 192.168.0.0/24) und brauchst z. B. 4 Abteilungen/VLANs.")
    netz = lies_netz(frage("Netz (z. B. 192.168.178.0/24)", "192.168.178.0/24"))
    try:
        n = int(frage("Wie viele Subnetze?", "4"))
    except ValueError:
        raise EingabeFehler("Bitte eine ganze Zahl eingeben.")
    if n < 1:
        raise EingabeFehler("Mindestens 1 Subnetz.")

    bits = math.ceil(math.log2(n)) if n > 1 else 0
    neuer_praefix = netz.prefixlen + bits
    if neuer_praefix > 32:
        raise EingabeFehler("Das geht nicht: Der Präfix würde größer als /32.")

    abschnitt("Rechenweg")
    ausgabe(f"  Gesucht: {n} Subnetze")
    ausgabe(f"  Geliehene Bits b mit 2^b ≥ {n}  ->  b = {c(bits, F.FETT)}   (2^{bits} = {2 ** bits})")
    ausgabe(f"  Neuer Präfix = {netz.prefixlen} + {bits} = {c('/' + str(neuer_praefix), F.FETT, F.GRUEN)}"
            f"   Maske {maske_aus_praefix(neuer_praefix)}")
    erklaere(
        warum="Subnetze entstehen, indem man Hostbits 'ausleiht' und zum Netzanteil macht. "
              "Jedes geliehene Bit verdoppelt die Zahl der Subnetze und halbiert deren Größe.",
        wie="b = aufgerundet log2(N). Neuer Präfix = alter Präfix + b.",
        wozu="Segmentierung: weniger Broadcasts, bessere Sicherheit (Firewall zwischen VLANs), klare Struktur.",
    )
    if 2 ** bits != n:
        achtung(f"{n} ist keine Zweierpotenz – es entstehen {2 ** bits} Subnetze, {2 ** bits - n} bleiben als Reserve.")
        tipp("Reserve ist kein Fehler, sondern Wachstumspuffer. Für verschieden große Bedarfe nimm VLSM (Punkt 4).")

    subnetze = list(netz.subnets(new_prefix=neuer_praefix))
    zeige_subnetze(netz, subnetze)


# ---------- Modus 3: Teilen nach Präfix --------------------------------------

def modus_teilen_praefix() -> None:
    kasten("3 · NETZ TEILEN NACH PRÄFIX  –  'Mach daraus lauter /27'")
    erklaere(wozu="Du weißt, wie GROSS die Subnetze sein sollen (z. B. je 30 Hosts) und willst sehen, wie viele es werden.")
    netz = lies_netz(frage("Netz (z. B. 10.0.0.0/24)", "10.0.0.0/24"))
    try:
        neu = int(frage("Ziel-Präfix (z. B. 27)", "27").lstrip("/"))
    except ValueError:
        raise EingabeFehler("Bitte eine Zahl zwischen 0 und 32 eingeben.")
    if neu < netz.prefixlen:
        raise EingabeFehler(f"/{neu} ist GRÖSSER als /{netz.prefixlen} – das wäre Zusammenfassen, nicht Teilen.")
    if neu > 32:
        raise EingabeFehler("Der Präfix darf höchstens 32 sein.")
    if neu - netz.prefixlen > 16:
        raise EingabeFehler("Das ergäbe über 65.000 Subnetze – bitte einen kleineren Unterschied wählen.")

    bits = neu - netz.prefixlen
    abschnitt("Rechenweg")
    ausgabe(f"  Geliehene Bits = {neu} - {netz.prefixlen} = {c(bits, F.FETT)}")
    ausgabe(f"  Anzahl Subnetze = 2^{bits} = {c(2 ** bits, F.FETT, F.GRUEN)}")
    ausgabe(f"  Hostbits je Subnetz = 32 - {neu} = {32 - neu}  ->  {2 ** (32 - neu)} Adressen, "
            f"{max(2 ** (32 - neu) - 2, 0) if neu <= 30 else (2 if neu == 31 else 1)} nutzbar")
    erklaere(
        warum="Zielgröße bestimmt den Präfix; die Anzahl ergibt sich aus der Differenz der Präfixe.",
        wie="Anzahl = 2^(neuer Präfix - alter Präfix).",
        wozu="Z. B. 'Jede Filiale bekommt ein /27' – du siehst sofort, wie viele Filialen ins Netz passen.",
    )
    subnetze = list(netz.subnets(new_prefix=neu))
    zeige_subnetze(netz, subnetze)


# ---------- Modus 4: VLSM ----------------------------------------------------

def modus_vlsm() -> None:
    kasten("4 · VLSM  –  Subnetze unterschiedlicher Größe (die Praxis!)")
    erklaere(
        warum="In echt braucht jedes Segment eine andere Größe: 100 Clients, 20 Server, 2 für den Router-Link.",
        wie="Größter Bedarf zuerst, dann der Reihe nach lückenlos aus dem Netz herausschneiden.",
        wozu="Spart Adressen und ist DIE typische Aufgabe in Prüfung und Projektplanung.",
    )
    basis = lies_netz(frage("Gesamtnetz (z. B. 192.168.0.0/24)", "192.168.0.0/24"))
    roh = frage("Bedarf an Hosts je Subnetz, mit Komma (z. B. 100,50,20,2)", "100,50,20,2")
    try:
        bedarf = [int(x) for x in roh.replace(";", ",").split(",") if x.strip()]
    except ValueError:
        raise EingabeFehler("Bitte nur Zahlen mit Komma, z. B. 100,50,20,2")
    if not bedarf or min(bedarf) < 1:
        raise EingabeFehler("Jedes Subnetz braucht mindestens 1 Host.")

    # Größte zuerst: so bleiben alle Blöcke automatisch korrekt ausgerichtet (Alignment).
    sortiert = sorted(enumerate(bedarf, 1), key=lambda x: x[1], reverse=True)

    abschnitt("Schritt 1 · Welcher Präfix passt zu welchem Bedarf?")
    plan = []
    for original_nr, hosts in sortiert:
        hb = hostbits_fuer(hosts)
        p = 32 - hb
        plan.append((original_nr, hosts, p))
        ausgabe(f"  Bedarf {hosts:>5} Hosts -> {hosts}+2 = {hosts + 2} Adressen -> 2^{hb} = {2 ** hb}"
                f"  ->  {c('/' + str(p), F.FETT, F.GRUEN)}", folge=4)
    erklaere(
        warum="+2 wegen Netz- und Broadcast-Adresse; dann auf die nächste Zweierpotenz aufrunden.",
        wozu="Du siehst direkt, wie viel 'Verschnitt' entsteht (Differenz zwischen Bedarf und Blockgröße).",
    )
    tipp("Punkt-zu-Punkt-Link (2 Hosts)? /30 klassisch, /31 modern (RFC 3021) – Gerät muss es unterstützen.")

    abschnitt("Schritt 2 · Lückenlos der Reihe nach vergeben")
    aktuell = int(basis.network_address)
    ende = int(basis.broadcast_address)
    ergebnis = []
    for original_nr, hosts, p in plan:
        groesse = 2 ** (32 - p)
        if aktuell % groesse:                        # nicht ausgerichtet -> zum nächsten Block springen
            aktuell += groesse - (aktuell % groesse)
        if aktuell + groesse - 1 > ende:
            achtung(f"Bedarf {hosts} Hosts passt NICHT mehr in {basis}! Größeres Gesamtnetz wählen.")
            break
        sub = ipaddress.ip_network(f"{ipaddress.IPv4Address(aktuell)}/{p}")
        ergebnis.append((original_nr, hosts, sub))
        aktuell += groesse

    if ergebnis:
        breit = passt(86)                            # Tabelle nur, wenn sie wirklich auf den Bildschirm passt
        if breit:
            ausgabe(c("  Nr  Bedarf  Netz                Erster Host     Letzter Host    Broadcast       Frei", F.FETT))
            ausgabe(c("  " + "─" * 82, F.GRAU))
        for original_nr, hosts, sub in ergebnis:
            d = beschreibe(sub)
            frei = d["nutzbare_hosts"] - hosts
            TABELLE.append({"nr": original_nr, "bedarf": hosts, **d})
            if breit:
                ausgabe(f"  {original_nr:>2}  {hosts:>6}  {d['netz']:<18}  {d['erster_host']:<15} "
                        f"{d['letzter_host']:<15} {d['broadcast']:<15} {frei:>4}")
            else:
                karte(original_nr, d, bedarf=hosts, frei=frei)
        belegt = sum(s.num_addresses for _, _, s in ergebnis)
        ausgabe("")
        ausgabe(f"  Belegt: {belegt} von {basis.num_addresses} Adressen "
                f"({100 * belegt / basis.num_addresses:.1f} %)")
        if aktuell <= ende:
            rest = ipaddress.summarize_address_range(ipaddress.IPv4Address(aktuell), basis.broadcast_address)
            ausgabe("  Noch frei: " + c(", ".join(str(r) for r in rest), F.GRUEN, F.FETT), folge=4)
            tipp("Freien Platz dokumentieren! Das ist Wachstumsreserve und verhindert Überschneidungen.")


# ---------- Modus 5: Gleiches Netz? ------------------------------------------

def modus_gleiches_netz() -> None:
    kasten("5 · GLEICHES NETZ?  –  Können zwei Hosts direkt miteinander reden?")
    erklaere(
        warum="Ein Host sendet direkt, wenn das Ziel im EIGENEN Netz liegt. Sonst geht das Paket zum Standardgateway.",
        wozu="Klassischer Fehler im Betrieb: falsche Maske oder Gateway außerhalb des Netzes -> 'es geht nicht'.",
    )
    a = frage("Host A (z. B. 192.168.10.77)", "192.168.10.77")
    b = frage("Host B (z. B. 192.168.10.130)", "192.168.10.130")
    m = frage("Präfix oder Maske (z. B. 26 oder 255.255.255.192)", "26").lstrip("/")
    na = lies_netz(f"{a}/{m}")
    nb = lies_netz(f"{b}/{m}")
    abschnitt("Vergleich der Netzadressen")
    ausgabe(f"  A: {a}  ->  Netz {c(na, F.FETT)}")
    ausgabe(f"  B: {b}  ->  Netz {c(nb, F.FETT)}")
    if na == nb:
        ok("Gleiches Netz -> A und B reden direkt (Switch genügt, kein Router).")
    else:
        achtung("Verschiedene Netze -> der Verkehr braucht einen Router/Gateway.")
        tipp("Prüfe auch: Liegt das Standardgateway im Netz von A? Sonst erreicht A es gar nicht.")


# ---------- Modus 6: Spickzettel ---------------------------------------------

def modus_spickzettel() -> None:
    kasten("6 · SPICKZETTEL  –  Das Wichtigste auf einen Blick")

    abschnitt("A · Präfix-Tabelle (die Zeilen /24 bis /30 musst du im Schlaf können)")
    breit = passt(62)
    if breit:
        ausgabe(c("  Präfix  Maske              Block  Adressen      Hosts", F.FETT))
        ausgabe(c("  " + "─" * 56, F.GRAU))
    else:
        ausgabe(c(f"  {'Präf.':<5}{'Maske':<16}{'Blk':>4} {'Hosts':>11}", F.FETT))
        ausgabe(c("  " + "─" * max(10, min(37, zeilenbreite() - 4)), F.GRAU))
    for p in range(8, 33):
        _, _, schritt = merkzahl(p)
        adressen = 2 ** (32 - p)
        hosts = adressen - 2 if p <= 30 else (2 if p == 31 else 1)
        if breit:
            zeile = f"  /{p:<6} {maske_aus_praefix(p):<18} {schritt:>5}  {adressen:>11,}  {hosts:>11,}".replace(",", ".")
        else:
            zeile = f"  {'/' + str(p):<5}{maske_aus_praefix(p):<16}{schritt:>4} {hosts:>11,}".replace(",", ".")
        ausgabe(c(zeile, F.GRUEN, F.FETT) if 24 <= p <= 30 else zeile)
    ausgabe(c("  Block = Schrittweite im 'interessanten' Oktett (256 - Maskenwert).", F.GRAU))

    abschnitt("B · Zweierpotenzen (Basis für alles)")
    ausgabe("  " + "  ".join(f"2^{i}={2 ** i}" for i in range(1, 11)))
    ausgabe("  Maskenoktett: 1 Bit=128 · 2=192 · 3=224 · 4=240 · 5=248 · 6=252 · 7=254 · 8=255")

    abschnitt("C · Private und spezielle IPv4-Bereiche (2026 unverändert)")
    for cidr, name, hinweis in V4_BEREICHE:
        ausgabe(f"  {cidr:<20} {name}", folge=4)
    tipp("Home-Router nutzen oft 192.168.178.0/24 oder 192.168.0.0/24. Wählst du im Firmen-VPN dasselbe "
         "-> Adresskonflikt! Plane lieber ungewöhnliche Bereiche wie 10.42.0.0/16.")

    abschnitt("D · Praxis-Tipps für Systemintegratoren")
    for p in (24, 26, 27, 28, 29, 30, 31, 32):
        ausgabe(f"  /{p:<3} {PRAXIS[p]}", folge=7)
    ausgabe("")
    for zeile in [
        "Ein VLAN = ein Subnetz = eine Broadcast-Domäne. Trenne Clients, Server, Management, Gäste, Telefonie.",
        "Gateway-Konvention: immer die erste (.1) ODER die letzte (.254) Adresse – im ganzen Unternehmen gleich!",
        "Reserviere feste Bereiche: z. B. .1–.20 Infrastruktur, .21–.99 statische Server, .100–.250 DHCP.",
        "Plane 20–30 % Wachstum ein. Subnetze nachträglich zu vergrößern ist teuer.",
        "Dokumentiere jedes Subnetz (Zweck, VLAN-ID, Gateway, DHCP-Bereich) – am besten in Git/Markdown.",
        "Im Zweifel mit 'ping' und 'ip a' / 'ipconfig' prüfen, ob Maske und Gateway wirklich stimmen.",
    ]:
        ausgabe("  • " + zeile, folge=4)

    abschnitt("E · Typische Fehler")
    for zeile in [
        "'-2' vergessen: Netzadresse und Broadcast sind keine Hostadressen (außer /31, /32).",
        "Hostbereich mit Netzbereich verwechseln: Das Netz endet NICHT bei der eingegebenen IP.",
        "Subnetze, die sich überlappen (z. B. 10.0.0.0/24 und 10.0.0.128/25) -> Routing-Chaos.",
        "Falsche Maske am Client: sieht 'nahe' Hosts nicht mehr oder hält Ferne für lokal.",
        "169.254.x.x am Client = kein DHCP erreichbar, nicht 'die IP ist kaputt'.",
        "Gateway liegt außerhalb des Client-Netzes.",
    ]:
        ausgabe("  ✗ " + zeile, folge=4)


# ---------- Modus 7: Quiz ----------------------------------------------------

def modus_quiz() -> None:
    kasten("7 · QUIZ  –  Training im Prüfungsstil (mit 'h' für einen Hinweis)")
    runden, punkte = 5, 0
    erklaere(wozu="Üben, bis die Merkzahl-Methode automatisch läuft. Antwort 'h' = Hinweis, 'q' = abbrechen.")

    basen = [ipaddress.ip_network(x) for x in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
    for nr in range(1, runden + 1):
        basis = random.choice(basen)
        ip = ipaddress.IPv4Address(int(basis.network_address) + random.randrange(basis.num_addresses))
        p = random.choice([20, 21, 22, 23, 25, 26, 27, 28, 29, 30])
        iface = ipaddress.ip_interface(f"{ip}/{p}")
        netz = iface.network
        art = random.choice(["netz", "broadcast", "hosts", "praefix"])
        idx, maskenwert, schritt = merkzahl(p)

        if art == "netz":
            text = f"Wie lautet die NETZADRESSE von {iface}?"
            loesung = str(netz.network_address)
            hinweis = f"Schrittweite im {idx + 1}. Oktett ist {schritt}. Oktett ÷ {schritt}, abrunden, × {schritt}."
            erkl = f"{iface.ip} UND {netz.netmask} = {netz.network_address}"
            norm = lambda s: str(ipaddress.ip_address(s))
        elif art == "broadcast":
            text = f"Wie lautet die BROADCAST-Adresse von {iface}?"
            loesung = str(netz.broadcast_address)
            hinweis = f"Erst das Netz bestimmen (Schrittweite {schritt}), dann nächstes Netz minus 1."
            erkl = f"Netz {netz.network_address} + {netz.num_addresses} Adressen - 1 = {netz.broadcast_address}"
            norm = lambda s: str(ipaddress.ip_address(s))
        elif art == "hosts":
            text = f"Wie viele NUTZBARE Hosts hat ein /{p}-Netz?"
            loesung = str(2 ** (32 - p) - 2)
            hinweis = f"Hostbits = 32 - {p}. Dann 2^Hostbits - 2."
            erkl = f"2^{32 - p} - 2 = {2 ** (32 - p)} - 2 = {2 ** (32 - p) - 2}"
            norm = lambda s: str(int(s.replace(".", "")))
        else:
            n = random.choice([10, 25, 50, 100, 200, 500])
            text = f"Welcher kleinste Präfix reicht für {n} Hosts?"
            loesung = str(32 - hostbits_fuer(n))
            hinweis = f"{n} + 2 = {n + 2} Adressen. Nächste Zweierpotenz? Daraus Hostbits, dann 32 - Hostbits."
            erkl = (f"{n}+2 = {n + 2} -> 2^{hostbits_fuer(n)} = {2 ** hostbits_fuer(n)} "
                    f"-> Präfix 32 - {hostbits_fuer(n)} = /{loesung}")
            norm = lambda s: str(int(s.lstrip("/")))

        abschnitt(f"Frage {nr} von {runden}")
        ausgabe("  " + c(text, F.FETT))
        hinweis_genutzt = False
        while True:
            antwort = input(c("➤ Antwort: ", F.GRUEN, F.FETT)).strip()
            if antwort.lower() == "q":
                ausgabe(c(f"  Abgebrochen. Zwischenstand: {punkte} Punkte.", F.GRAU))
                return
            if antwort.lower() == "h" and not hinweis_genutzt:
                tipp(hinweis)
                hinweis_genutzt = True
                continue
            break
        try:
            richtig = norm(antwort) == norm(loesung)
        except ValueError:
            richtig = False
        if richtig:
            punkte += 1
            ok("Richtig! " + erkl)
        else:
            ausgabe(c("  ✘ Leider nicht. ", F.ROT, F.FETT) + f"Richtig wäre {c(loesung, F.FETT)}.", folge=4)
            ausgabe(f"    Rechenweg: {erkl}", folge=6)

    abschnitt("Ergebnis")
    balken = "█" * punkte + "░" * (runden - punkte)
    ausgabe(f"  {c(balken, F.GRUEN)}  {punkte} / {runden}")
    if punkte == runden:
        ausgabe(c("  🏆 Perfekt! Du bist bereit für die Prüfung.", F.GRUEN, F.FETT), folge=5)
    elif punkte >= 3:
        ausgabe(c("  👍 Gut! Noch eine Runde, dann sitzt es.", F.GELB, F.FETT), folge=5)
    else:
        ausgabe(c("  🌱 Kein Problem – schau dir Menüpunkt 1 an und probiere es nochmal. Üben macht den Meister.",
                  F.CYAN, F.FETT), folge=5)


# ---------- Modus 8: IPv6 ----------------------------------------------------

V6_TYPEN = [
    ("::/128", "Unspezifizierte Adresse (::)", "'ich habe noch keine Adresse' – nur als Absender beim Start"),
    ("::1/128", "Loopback (::1)", "der eigene Rechner, Pendant zu 127.0.0.1"),
    ("::ffff:0:0/96", "IPv4-mapped", "IPv4-Adresse in IPv6-Schreibweise (Übergangstechnik)"),
    ("64:ff9b::/96", "NAT64-Präfix", "Übersetzung zwischen IPv6 und IPv4"),
    ("2001:db8::/32", "Dokumentation", "nur für Beispiele – nie echt verwenden"),
    ("2002::/16", "6to4 (veraltet)", "alter Tunnelmechanismus"),
    ("2000::/3", "Global Unicast (öffentlich)", "im Internet routbar, Pendant zu 'öffentliche IPv4'"),
    ("fc00::/7", "Unique Local Address (ULA)", "privat, Pendant zu RFC 1918 (in der Praxis fd00::/8)"),
    ("fe80::/10", "Link-Local", "gilt nur im eigenen Segment, automatisch auf JEDEM IPv6-Interface"),
    ("ff00::/8", "Multicast", "Gruppenadresse; ersetzt Broadcast (ff02::1 = alle Hosts, ff02::2 = alle Router)"),
]


def klassifiziere_v6(adr: ipaddress.IPv6Address) -> tuple[str, str]:
    beste = None
    for cidr, name, hinweis in V6_TYPEN:
        netz = ipaddress.ip_network(cidr)
        if adr in netz and (beste is None or netz.prefixlen > beste[0].prefixlen):
            beste = (netz, name, hinweis)
    return (beste[1], beste[2]) if beste else ("Reserviert/unbekannt", "nicht aus den üblichen Bereichen")


def modus_ipv6() -> None:
    kasten("8 · IPv6  –  die Grundlagen")
    ausgabe("  a) Grundlagen und Regeln")
    ausgabe("  b) Adresse analysieren (Kurzschreibweise, Typ, Netz)")
    ausgabe("  c) Ein Netz in /64-Subnetze teilen (z. B. /48 oder /56 vom Provider)")
    wahl = frage("Auswahl", "a").lower()
    if wahl == "a":
        ipv6_grundlagen()
    elif wahl == "b":
        ipv6_analyse()
    elif wahl == "c":
        ipv6_teilen()
    else:
        raise EingabeFehler("Bitte a, b oder c wählen.")


def ipv6_grundlagen() -> None:
    abschnitt("Was ist neu an IPv6?")
    for zeile in [
        "128 Bit statt 32 Bit, geschrieben als 8 Gruppen aus je 4 Hex-Ziffern: 2001:0db8:abcd:0012:0000:0000:0000:0001",
        "Jede Hex-Ziffer = 4 Bit (ein 'Nibble'). 32 Hex-Ziffern × 4 Bit = 128 Bit.",
        "Kein Broadcast mehr! Stattdessen Multicast (ff02::1 = alle Hosts im Segment).",
        "Kein 'Netz-/Broadcast-Abzug': die Adressen eines /64 sind praktisch unerschöpflich (2^64).",
        "Jedes Interface hat IMMER eine Link-Local-Adresse (fe80::/10) – ohne jede Konfiguration.",
        "Ein Interface hat meist MEHRERE Adressen gleichzeitig (Link-Local, global, ggf. ULA).",
        "NAT ist nicht nötig; Schutz kommt von der Firewall, nicht von Adressübersetzung.",
    ]:
        ausgabe("  • " + zeile, folge=4)

    abschnitt("Die Aufteilung (das Wichtigste, was du dir merken musst)")
    if passt(74):
        ausgabe("  |<------ 48 Bit ------>|<- 16 ->|<------------ 64 Bit ------------>|")
        ausgabe("  |   Provider-Präfix     | Subnetz|        Interface-ID (Host)       |")
        ausgabe("  |    z. B. /48 o. /56   |  -ID   |  (fest 64 Bit im LAN)            |")
    else:
        ausgabe("  Provider-Präfix : z. B. 48 oder 56 Bit")
        ausgabe("  Subnetz-ID      : 16 Bit (beim /48)")
        ausgabe("  Interface-ID    : 64 Bit (fest im LAN)")
    erklaere(
        warum="Ein LAN-Segment ist praktisch IMMER ein /64. SLAAC (automatische Adressvergabe) und "
              "Neighbor Discovery setzen das voraus.",
        wozu="Subnetting bei IPv6 heißt: Du verteilst die Subnetz-ID (Bits 49–64) auf deine VLANs – kein Rechnen mit Hosts.",
    )
    tipp("Provider geben meist ein /56 oder /48 (hängt vom Provider ab). Ein /56 enthält 2^8 = 256 mögliche /64-Netze, ein /48 enthält 65.536.")

    abschnitt("Schreibregeln (Kurzschreibweise)")
    erklaere(wie="1) Führende Nullen in jeder Gruppe weglassen.  2) EINMAL eine Folge reiner Null-Gruppen durch '::' ersetzen "
                 "(die längste; bei Gleichstand die erste).")
    ausgabe("  2001:0db8:0000:0000:0000:0000:0000:0001  ->  " + c("2001:db8::1", F.GRUEN, F.FETT), folge=4)
    achtung("'::' darf nur EINMAL vorkommen, sonst ist die Adresse nicht eindeutig!")

    abschnitt("Die Adresstypen")
    for cidr, name, hinweis in V6_TYPEN:
        ausgabe(f"  {cidr:<16} {name}", folge=4)
    tipp("Erkennen am Anfang: 2… = global · fe80 = Link-Local · fd… = ULA (privat) · ff… = Multicast.")


def ipv6_analyse() -> None:
    eingabe = frage("IPv6-Adresse mit Präfix (z. B. 2001:db8:abcd:12::1/64)", "2001:db8:abcd:12::1/64")
    try:
        iface = ipaddress.ip_interface(eingabe.strip())
    except ValueError:
        raise EingabeFehler("Keine gültige IPv6-Adresse. Beispiel: 2001:db8:abcd:12::1/64")
    if iface.version != 6:
        raise EingabeFehler("Das ist IPv4 – nimm Menüpunkt 1.")
    adr, netz = iface.ip, iface.network
    p = netz.prefixlen

    abschnitt("Ergebnis")
    ausgabe(f"  Ausgeschrieben: {adr.exploded}", folge=4)
    ausgabe(f"  Kurzform:       {c(adr.compressed, F.FETT, F.GRUEN)}", folge=4)
    ausgabe(f"  Netz:           {c(netz.compressed, F.FETT)}  (Präfix /{p})", folge=4)
    typ, hinweis = klassifiziere_v6(adr)
    ausgabe(f"  Typ:            {c(typ, F.FETT)}", folge=4)
    ausgabe(f"  Info:           {hinweis}", folge=4)
    ausgabe(f"  Adressen im Netz: 2^{128 - p} = {2 ** (128 - p):,}".replace(",", "."), folge=4)

    abschnitt("Netz- und Hostanteil")
    hexziffern = adr.exploded.replace(":", "")
    netzanteil = p // 4
    ausgabe(f"  Jede Hex-Ziffer = 4 Bit -> {p} Bit = {p // 4} Ziffern" + (f" + {p % 4} Bit" if p % 4 else ""), folge=4)
    ausgabe("  " + c(hexziffern[:netzanteil], F.CYAN, F.FETT) + c(hexziffern[netzanteil:], F.MAGENTA, F.FETT)
            + "   " + c("■ Netz", F.CYAN) + " " + c("■ Host", F.MAGENTA), folge=4)
    if p % 4:
        tipp("Präfixe, die kein Vielfaches von 4 sind, enden mitten in einer Hex-Ziffer – schwer lesbar. "
             "Bevorzuge /48, /52, /56, /60, /64.")
    if p == 64:
        tipp("Bei /64: die letzten 64 Bit (16 Hex-Ziffern) sind die Interface-ID – per SLAAC automatisch oder manuell/DHCPv6.")
    TABELLE.append({"adresse": adr.compressed, "netz": str(netz), "typ": typ})


def ipv6_teilen() -> None:
    try:
        netz = ipaddress.ip_network(frage("Netz vom Provider (z. B. 2001:db8:abcd::/48)", "2001:db8:abcd::/48").strip(),
                                    strict=False)
    except ValueError:
        raise EingabeFehler("Kein gültiges Netz. Beispiel: 2001:db8:abcd::/48")
    if netz.version != 6:
        raise EingabeFehler("Das ist IPv4 – nimm Menüpunkt 2 oder 3.")
    try:
        neu = int(frage("Ziel-Präfix", "64").lstrip("/"))
    except ValueError:
        raise EingabeFehler("Bitte eine Zahl eingeben.")
    if neu < netz.prefixlen or neu > 128:
        raise EingabeFehler(f"Der Ziel-Präfix muss zwischen /{netz.prefixlen} und /128 liegen.")

    bits = neu - netz.prefixlen
    abschnitt("Rechenweg")
    ausgabe(f"  Geliehene Bits = {neu} - {netz.prefixlen} = {c(bits, F.FETT)}")
    ausgabe(f"  Anzahl Subnetze = 2^{bits} = {c(f'{2 ** bits:,}'.replace(',', '.'), F.FETT, F.GRUEN)}")
    erklaere(
        warum="Genau wie bei IPv4: Bits aus dem Hostanteil werden zum Netzanteil. Nur ist der Hostanteil riesig.",
        wozu="Beispiel: /56 vom Provider -> 8 Bit Subnetz-ID -> 256 VLANs mit je einem /64.",
    )
    abschnitt("Die ersten Subnetze")
    for nr, s in enumerate(islice(netz.subnets(new_prefix=neu), 16), 1):
        ausgabe(f"  {nr:>3}.  {s.compressed}", folge=7)
        TABELLE.append({"nr": nr, "netz": str(s)})
    if bits and 2 ** bits > 16:
        ausgabe(c(f"  … und {2 ** bits - 16:,} weitere".replace(",", "."), F.GRAU))
    tipp("Praktisch: Nimm als Subnetz-ID die VLAN-ID in Hex (z. B. VLAN 20 -> ...:0014::/64). Dann erkennst du das VLAN an der Adresse.")


# ---------- Modus 9: Export --------------------------------------------------

def modus_export() -> None:
    kasten("9 · SPEICHERN  –  Notizen (.md) und Tabelle (.csv)")
    if not PROTOKOLL:
        ausgabe("  Es gibt noch nichts zu speichern. Rechne zuerst etwas (Punkte 1–8).")
        return
    ordner = Path.home() / "Schreibtisch"
    if not ordner.exists():
        ordner = Path.home() / "Desktop"
    if not ordner.exists():
        ordner = Path.home()
    ordner_text = frage("Zielordner", str(ordner))
    ziel = Path(ordner_text).expanduser()
    if not ziel.is_dir():
        raise EingabeFehler(f"Der Ordner {ziel} existiert nicht.")

    stempel = datetime.now().strftime("%Y%m%d_%H%M%S")
    md = ziel / f"subnetting_{stempel}.md"
    md.write_text("# Subnetting-Notizen\n\n```text\n" + "\n".join(PROTOKOLL) + "\n```\n", encoding="utf-8")
    ok(f"Notizen:  {md}")
    if TABELLE:
        csvp = ziel / f"subnetting_{stempel}.csv"
        felder: list[str] = []
        for zeile in TABELLE:
            for k in zeile:
                if k not in felder:
                    felder.append(k)
        with csvp.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=felder, delimiter=";")   # ; = deutsches Excel/LibreOffice
            w.writeheader()
            w.writerows(TABELLE)
        ok(f"Tabelle:  {csvp}  (Trennzeichen ';')")


# =============================================================================
# 4b. PYTHON-LERNECKE (Menüpunkt 10)
#     Hier lernst du Python an DEM Code, den du gerade benutzt – mit echten Werten.
# =============================================================================

def zeige_code(zeilen: list[str]) -> None:
    """Zeigt Beispielcode so, wie man ihn im Python-Terminal tippen würde."""
    for code_text in zeilen:
        ausgabe(c("    │ ", F.GRAU) + c(code_text, F.CYAN), folge=8)


def code_zeile(code: str, text: str) -> None:
    """Eine Codezeile aus dem Tool (gelber Pfeil) mit ihrer Erklärung darunter."""
    ausgabe("")
    ausgabe(c("  ▶ ", F.GELB, F.FETT) + c(code, F.CYAN, F.FETT), folge=6)
    if text:
        ausgabe("      " + text, folge=6)


def teil_schritt(text: str) -> None:
    """Ein Teilschritt innerhalb einer Codezeile (was passiert in welcher Reihenfolge?)."""
    if not passt(95):                               # schmal: Ausrichtungs-Leerzeichen sparen Platz
        text = re.sub(r" {2,}", " ", text)
    ausgabe(c("        · ", F.MAGENTA) + text, folge=10)


def modus_python() -> None:
    kasten("10 · PYTHON-LERNECKE  –  der Code dieses Tools, erklärt")
    erklaere(wozu="Du lernst Python an einem echten Werkzeug, das du selbst benutzt. Alle Zahlen unten "
                  "werden live berechnet – nichts ist erfunden.")
    ausgabe("  a) Python-Bausteine mit Live-Beispielen (Variablen, Schleifen, Funktionen …)", folge=5)
    ausgabe("  b) Kernfunktionen des Tools Zeile für Zeile erklärt", folge=5)
    wahl = frage("Auswahl", "a").lower()
    if wahl == "a":
        python_bausteine()
    elif wahl == "b":
        python_zeilen()
    else:
        raise EingabeFehler("Bitte a oder b wählen.")


def python_bausteine() -> None:
    # Beispielwerte, die in den Bausteinen wirklich ausgerechnet werden
    ip, praefix = "192.168.10.77", 26
    netz = ipaddress.ip_network(f"{ip}/{praefix}", strict=False)
    zahl = int(ipaddress.IPv4Address(ip))
    maske = int(netz.netmask)
    d = beschreibe(netz)

    def quadrat(x):                      # kleine Beispiel-Funktion für Baustein 8
        return x * x

    try:                                 # Beispiel für Baustein 9: einen Fehler absichtlich auslösen
        ipaddress.ip_network("300.1.1.1/24")
        fehler_text = "gültig"
    except ValueError:
        fehler_text = "keine gültige Adresse"

    # Jeder Baustein: (Titel, Erklärung, Wozu im Tool, Beispielcode, echte Ergebnisse)
    bausteine = [
        ("Variablen und f-Strings",
         "Eine Variable ist ein Name für einen Wert. Ein f-String (f vor dem Text) setzt Werte in {} in den Text ein.",
         "Fast jede Ausgabe des Tools ist ein f-String, z. B. f\"Hostbits = 32 - {p} = {h}\".",
         ['ip = "192.168.10.77"', "praefix = 26", 'text = f"{ip}/{praefix}"', "print(text)"],
         [f"{ip}/{praefix}"]),
        ("Rechnen: Potenzen und Aufrunden",
         "** ist 'hoch'. math.log2 ist der Zweierlogarithmus, math.ceil rundet auf.",
         "Daraus entstehen Hostzahl (2^Hostbits - 2) und die Wahl des Präfixes bei VLSM.",
         ["import math", "print(2 ** (32 - 26) - 2)", "print(math.ceil(math.log2(100 + 2)))"],
         [str(2 ** (32 - praefix) - 2), str(math.ceil(math.log2(102)))]),
        ("Das Modul ipaddress",
         "Ein Modul ist eine fertige Werkzeugkiste. ipaddress kennt Netze, Masken und Adressen. "
         "strict=False erlaubt Hostbits in der Eingabe.",
         "Damit macht das Tool aus 192.168.10.77/26 das echte Netz 192.168.10.64/26.",
         ["import ipaddress", 'netz = ipaddress.ip_network("192.168.10.77/26", strict=False)',
          "print(netz)", "print(netz.netmask)", "print(netz.num_addresses)"],
         [str(netz), str(netz.netmask), str(netz.num_addresses)]),
        ("Eine IP-Adresse ist eine Zahl",
         "Intern ist jede IPv4-Adresse eine 32-Bit-Zahl. f\"{zahl:032b}\" schreibt sie binär mit 32 Stellen.",
         "So entsteht die farbige Binärdarstellung in Menüpunkt 1.",
         ['zahl = int(ipaddress.IPv4Address("192.168.10.77"))', "print(zahl)", 'print(f"{zahl:032b}")'],
         [str(zahl), f"{zahl:032b}"]),
        ("Bit-Operationen: UND und XOR",
         "& ist das bitweise UND (1 nur, wenn beide Bits 1 sind). ^ ist XOR (Bit umdrehen, wenn das andere Bit 1 ist). "
         "0xFFFFFFFF ist Hex-Schreibweise für 32 Einsen.",
         "IP UND Maske = Netzadresse. Maske XOR 32 Einsen = Wildcard.",
         ["maske = int(netz.netmask)", "print(ipaddress.IPv4Address(zahl & maske))",
          "print(ipaddress.IPv4Address(maske ^ 0xFFFFFFFF))"],
         [str(ipaddress.IPv4Address(zahl & maske)), str(ipaddress.IPv4Address(maske ^ 0xFFFFFFFF))]),
        ("Listen und Schleifen",
         "Eine Liste enthält mehrere Werte. for geht sie nacheinander durch. enumerate(..., 1) zählt mit, ab 1.",
         "So entstehen die Tabellen beim Teilen von Netzen.",
         ["for nr, s in enumerate(netz.subnets(new_prefix=28), 1):", "    print(nr, s)"],
         [f"{nr} {s}" for nr, s in enumerate(netz.subnets(new_prefix=28), 1)]),
        ("Dictionary (Wörterbuch)",
         "Ein Dictionary speichert Paare aus Schlüssel und Wert: {\"schlüssel\": wert}. Zugriff mit d[\"schlüssel\"].",
         "beschreibe(netz) liefert alle Netzdaten in so einem Dictionary – die Tabellen lesen daraus.",
         ["d = beschreibe(netz)", 'print(d["broadcast"])', 'print(d["nutzbare_hosts"])'],
         [str(d["broadcast"]), str(d["nutzbare_hosts"])]),
        ("Funktionen",
         "def baut einen wiederverwendbaren Baustein. return gibt das Ergebnis zurück. "
         "Einmal schreiben, überall benutzen.",
         "Das ganze Tool besteht aus kleinen Funktionen wie hostbits_fuer() oder beschreibe().",
         ["def quadrat(x):", "    return x * x", "print(quadrat(7))"],
         [str(quadrat(7))]),
        ("try / except (Fehler abfangen)",
         "Was in try schiefgeht, landet in except – statt dass das Programm abstürzt.",
         "Deshalb zeigt das Tool bei Tippfehlern eine freundliche Meldung statt eines Python-Fehlers.",
         ["try:", '    ipaddress.ip_network("300.1.1.1/24")', "except ValueError:",
          '    print("keine gültige Adresse")'],
         [fehler_text]),
    ]

    for nr, (titel, text, wozu, code, ergebnis) in enumerate(bausteine, 1):
        abschnitt(f"Baustein {nr} von {len(bausteine)} · {titel}")
        ausgabe("  " + text)
        erklaere(wozu=wozu)
        zeige_code(code)
        for zeile_text in ergebnis:
            ausgabe(c("    ➜ ", F.GRUEN, F.FETT) + zeile_text, folge=6)
    tipp("Probiere die Beispiele selbst aus: tippe 'python3' im Terminal und füge die Codezeilen ein. "
         "Beenden mit exit().")


def python_zeilen() -> None:
    # Beispielwerte, mit denen jede Zeile unten wirklich durchgerechnet wird
    ip, praefix, hosts = "192.168.10.77", 26, 100
    netz = ipaddress.ip_network(f"{ip}/{praefix}", strict=False)

    # ---------- Funktion 1: wildcard_aus_maske ----------
    abschnitt("Funktion 1 · wildcard_aus_maske  (Maske umdrehen)")
    m = int(netz.netmask)
    w = m ^ 0xFFFFFFFF
    code_zeile("def wildcard_aus_maske(maske: ipaddress.IPv4Address) -> str:",
               "def definiert die Funktion. In Klammern steht, was sie bekommt (maske). "
               "': ipaddress.IPv4Address' ist nur ein Typ-Hinweis (Doku, Python erzwingt ihn nicht). "
               "'-> str' heißt: sie gibt Text zurück.")
    code_zeile("return str(ipaddress.IPv4Address(int(maske) ^ 0xFFFFFFFF))",
               "Wird von innen nach außen gelesen:")
    teil_schritt(f"int(maske)                    -> Adresse als Zahl: {m}")
    teil_schritt(f"... ^ 0xFFFFFFFF              -> XOR mit 32 Einsen dreht jedes Bit um: {w}")
    teil_schritt(f"ipaddress.IPv4Address(...)    -> Zahl wieder als IP: {ipaddress.IPv4Address(w)}")
    teil_schritt(f"str(...)                      -> als Text: '{ipaddress.IPv4Address(w)}'")
    teil_schritt("return                       -> gibt dieses Ergebnis an den Aufrufer zurück")

    # ---------- Funktion 2: hostbits_fuer ----------
    abschnitt("Funktion 2 · hostbits_fuer  (wie viele Hostbits brauche ich?)")
    code_zeile("def hostbits_fuer(hosts: int) -> int:",
               "Bekommt die Zahl der gewünschten Hosts, gibt eine ganze Zahl (Hostbits) zurück.")
    code_zeile("return max(2, math.ceil(math.log2(hosts + 2)))",
               f"Beispiel hosts = {hosts}. Wieder von innen nach außen:")
    teil_schritt(f"hosts + 2                     -> {hosts + 2}  (plus Netzadresse und Broadcast)")
    teil_schritt(f"math.log2({hosts + 2})               -> {math.log2(hosts + 2):.3f}  (2 hoch wieviel ergibt {hosts + 2}?)")
    teil_schritt(f"math.ceil(...)                -> {math.ceil(math.log2(hosts + 2))}  (aufrunden, denn Bits gibt es nur ganz)")
    teil_schritt(f"max(2, ...)                   -> {hostbits_fuer(hosts)}  (mindestens 2 Hostbits, kleinstes sinnvolles Netz ist /30)")
    teil_schritt(f"Probe: 2^{hostbits_fuer(hosts)} = {2 ** hostbits_fuer(hosts)} Adressen >= {hosts + 2}  ✔  -> Präfix /{32 - hostbits_fuer(hosts)}")

    # ---------- Funktion 3: merkzahl ----------
    abschnitt("Funktion 3 · merkzahl  (Kopfrechen-Methode)")
    idx, maskenwert, schritt = merkzahl(praefix)
    rest = praefix - 8 * min(praefix // 8, 3)
    code_zeile("idx = min(praefix // 8, 3)",
               f"// ist die ganzzahlige Division (ohne Rest): {praefix} // 8 = {praefix // 8}. "
               f"min(..., 3) begrenzt auf 3 (das 4. Oktett). Ergebnis idx = {idx} (Zählung ab 0!).")
    code_zeile("rest = praefix - 8 * idx if praefix < 32 else 8",
               f"Das ist ein bedingter Ausdruck: 'A if Bedingung else B'. Hier: {praefix} - 8 * {idx} = {rest} "
               "Einsen im interessanten Oktett (bei /32 wären es 8).")
    code_zeile("maskenwert = (256 - 2 ** (8 - rest)) if rest > 0 else 0",
               f"2 ** (8 - {rest}) = {2 ** (8 - rest)}, dann 256 - {2 ** (8 - rest)} = {maskenwert}. "
               "Das ist der Wert des Masken-Oktetts (bei 0 Einsen: 0).")
    code_zeile("return idx, maskenwert, 256 - maskenwert",
               f"Python kann mehrere Werte zurückgeben (ein Tupel): ({idx}, {maskenwert}, {schritt}). "
               f"Die Schrittweite {schritt} = 256 - {maskenwert} ist die Blockgröße.")

    # ---------- Funktion 4: binaer_farbig ----------
    abschnitt("Funktion 4 · binaer_farbig  (die farbigen Bits)")
    bits = f"{int(ipaddress.IPv4Address(ip)):032b}"
    code_zeile('bits = f"{wert:032b}"',
               f"Zahl als Binärtext mit 32 Stellen (auffüllen mit 0): {bits}")
    code_zeile("teile = []", "Eine leere Liste. Hier sammeln wir Zeichen für Zeichen das Ergebnis.")
    code_zeile("for i, bit in enumerate(bits):",
               "Geht alle 32 Zeichen durch. enumerate liefert zusätzlich den Zähler i (0, 1, 2 …).")
    code_zeile("    if i and i % 8 == 0:",
               f"% ist der Rest einer Division. i % 8 == 0 trifft bei i = 8, 16, 24 zu – also nach jedem Oktett. "
               f"'i and ...': bei i = 0 ist i 'falsch' (0), so entsteht kein Punkt am Anfang. "
               f"Beispiel: bits[:8] = {bits[:8]}, bits[8:16] = {bits[8:16]}.")
    code_zeile('        teile.append(".")', "Hängt einen Punkt an die Liste an.")
    code_zeile("    teile.append(c(bit, F.CYAN) if i < praefix else c(bit, F.MAGENTA))",
               f"Wieder ein bedingter Ausdruck: Bit {praefix} und davor (i < {praefix}) = Netzanteil = cyan, danach "
               "= Hostanteil = magenta. c() färbt den Text.")
    code_zeile('return "".join(teile)',
               'join klebt alle Listenelemente zu EINEM Text zusammen ("" = ohne Trennzeichen dazwischen).')

    # ---------- Funktion 5: ausgabe ----------
    abschnitt("Funktion 5 · ausgabe  (drucken UND merken)")
    code_zeile('def ausgabe(text: str = "") -> None:',
               "text = \"\" ist ein Standardwert: ruft man ausgabe() ohne Text auf, gibt es eine Leerzeile. "
               "'-> None' heißt: die Funktion gibt nichts zurück, sie tut nur etwas.")
    code_zeile("print(text)", "Zeigt den Text im Terminal.")
    code_zeile('PROTOKOLL.append(ANSI_RE.sub("", text))',
               "ANSI_RE.sub(\"\", text) entfernt die Farbcodes per regulärem Ausdruck, .append hängt die saubere "
               "Zeile an die Liste PROTOKOLL. Daraus baut Menüpunkt 9 später deine .md-Notizen.")
    tipp("Den ganzen Code findest du in der Datei selbst – jede Funktion hat einen Docstring (der Text in \"\"\") "
         "und Kommentare nach #. Lies sie von oben nach unten: erst die kleinen Bausteine, dann die Modi.")


# =============================================================================
# 4c. KOMMANDOZEILE  –  subnetear 10.0.0.0/24 -n 4  (ohne Menü)
# =============================================================================

class DeutscherParser(argparse.ArgumentParser):
    """argparse meldet Fehler normalerweise auf Englisch und beendet das Programm.
    Wir überschreiben error(): freundliche deutsche Meldung über unsere EingabeFehler-Klasse."""

    def error(self, message):
        raise EingabeFehler(f"Den Befehl habe ich nicht verstanden ({message}). Hilfe: subnetear --hilfe")


def baue_parser() -> argparse.ArgumentParser:
    p = DeutscherParser(prog="subnetear", add_help=False)
    p.add_argument("cidr", nargs="?")                       # nargs="?" = optional (Menü startet ohne)
    p.add_argument("ziel", nargs="?")                       # Ziel-Präfix, z. B. /27
    p.add_argument("-n", "--anzahl", type=int)              # type=int wandelt den Text in eine Zahl
    p.add_argument("--vlsm")                                # z. B. "100,50,20,2"
    p.add_argument("--speichern", metavar="ORDNER")         # danach .md/.csv in diesen Ordner schreiben
    p.add_argument("--python", action="store_true")         # store_true: Schalter ohne Wert
    p.add_argument("--ohne-animation", action="store_true")
    p.add_argument("-h", "--hilfe", action="store_true")
    return p


def zeige_hilfe() -> None:
    """Hilfe: jeder Befehl in einer Zeile, die Beschreibung darunter – so passt es auf jeden Bildschirm."""
    drucke("")
    drucke(c("SUBNETEAR", F.FETT, F.GELB) + " – Subnetting-Trainer und -Rechner (IPv4, VLSM, IPv6)", 2)
    drucke("")
    drucke(c("Aufruf", F.FETT))
    for befehl, text in [
        ("subnetear", "Menü mit allen Funktionen"),
        ("subnetear <IP/Präfix>", "Schnellanalyse, Schritt für Schritt"),
        ("subnetear <Netz> <Ziel-Präfix>", "Netz in lauter gleich große Subnetze teilen"),
        ("subnetear <Netz> -n <Anzahl>", "Netz in N Subnetze teilen"),
        ("subnetear <Netz> --vlsm <Hosts,Hosts,...>", "Verschieden große Subnetze (VLSM)"),
    ]:
        drucke("  " + c(befehl, F.CYAN), 6)
        drucke("      " + text, 6)
    drucke("")
    drucke(c("Beispiele", F.FETT))
    for beispiel in [
        "subnetear 192.168.10.77/26",
        "subnetear 10.0.0.0/24 /27",
        "subnetear 10.0.0.0/24 -n 4",
        "subnetear 192.168.0.0/24 --vlsm 100,50,20,2",
        "subnetear 2001:db8:abcd::/48 /64           (IPv6 teilen)",
        "subnetear 2001:db8:abcd:12::1/64           (IPv6 analysieren)",
    ]:
        drucke("  " + beispiel, 6)
    drucke("")
    drucke(c("Weitere Optionen", F.FETT))
    for option, text in [
        ("--speichern ORDNER", "danach Notizen (.md) und Tabelle (.csv) in ORDNER ablegen"),
        ("--python", "Python-Lernecke: der Code dieses Tools, erklärt"),
        ("--ohne-animation", "keine Animationen (z. B. zum Kopieren)"),
        ("-h, --hilfe", "diese Hilfe"),
    ]:
        drucke("  " + c(option, F.CYAN), 6)
        drucke("      " + text, 6)
    drucke("")
    drucke(c("Hinweise", F.FETT))
    for hinweis in [
        "Der Präfix darf mit oder ohne Schrägstrich stehen: /27 oder 27.",
        "Bei IPv6 wird nach Präfix geteilt (nicht mit -n).",
        "Jede Ausgabe erklärt Warum, Wie und Wozu.",
        "Das Tool passt sich automatisch an die Bildschirmbreite an (Handy, Laptop, SSH).",
    ]:
        drucke("  • " + hinweis, 4)
    drucke("")


def cli_ausfuehren(args) -> None:
    """Übersetzt den Terminal-Befehl in die passende Funktion.
    Trick: Wir legen die Antworten in VORGABEN, die Modi 'fragen' dann nicht mehr, sondern lesen sie dort."""
    if args.python:
        modus_python()
        return
    if not args.cidr:
        raise EingabeFehler("Bitte ein Netz oder eine Adresse angeben, z. B. subnetear 192.168.10.77/26")

    ist_v6 = ":" in args.cidr                      # IPv6-Adressen enthalten Doppelpunkte, IPv4 nie

    if args.vlsm:
        if ist_v6:
            raise EingabeFehler("VLSM ist hier nur für IPv4 gedacht. Bei IPv6 gibt jedes Segment ein /64.")
        if args.ziel or args.anzahl is not None:
            raise EingabeFehler("--vlsm lässt sich nicht mit Ziel-Präfix oder -n kombinieren.")
        VORGABEN[:] = [args.cidr, args.vlsm]
        funktion, menuepunkt = modus_vlsm, "4"
    elif args.anzahl is not None:
        if ist_v6:
            raise EingabeFehler("Bei IPv6 teilt man nach Präfix: subnetear 2001:db8:abcd::/48 /64")
        if args.ziel:
            raise EingabeFehler("-n und Ziel-Präfix gleichzeitig geht nicht – wähle eins von beiden.")
        VORGABEN[:] = [args.cidr, str(args.anzahl)]
        funktion, menuepunkt = modus_teilen_anzahl, "2"
    elif args.ziel:
        VORGABEN[:] = [args.cidr, args.ziel]
        funktion, menuepunkt = (ipv6_teilen, "8 → c") if ist_v6 else (modus_teilen_praefix, "3")
    else:
        VORGABEN[:] = [args.cidr]
        funktion, menuepunkt = (ipv6_analyse, "8 → b") if ist_v6 else (modus_analyse, "1")

    funktion()
    ausgabe("")
    tipp(f"Das Gleiche gibt es interaktiv im Menü (Punkt {menuepunkt}). "
         "Mit 'subnetear --python' lernst du, wie der Code dahinter funktioniert.")

    if args.speichern:
        VORGABEN[:] = [args.speichern]
        modus_export()


# =============================================================================
# 5. HAUPTPROGRAMM
# =============================================================================

MENUE = [
    ("1", "IP-Analyse (Schritt für Schritt mit Binär)", modus_analyse),
    ("2", "Netz teilen nach Anzahl der Subnetze", modus_teilen_anzahl),
    ("3", "Netz teilen nach Ziel-Präfix", modus_teilen_praefix),
    ("4", "VLSM – unterschiedlich große Subnetze", modus_vlsm),
    ("5", "Gleiches Netz? (Host A ↔ Host B)", modus_gleiches_netz),
    ("6", "Spickzettel, Praxis-Tipps, typische Fehler", modus_spickzettel),
    ("7", "Quiz im Prüfungsstil", modus_quiz),
    ("8", "IPv6 – Grundlagen, Analyse, Teilen", modus_ipv6),
    ("9", "Speichern (.md und .csv)", modus_export),
    ("10", "Python-Lernecke (der Code, erklärt)", modus_python),
    ("0", "Beenden", None),
]


def banner() -> None:
    bitregen()
    w = breite()
    titel = "S U B N E T T I N G   M E I S T E R   2 0 2 6"
    untertitel = "IPv4 · VLSM · IPv6  –  verstehen statt auswendig lernen"
    if w < len(titel) + 4:                     # schmaler Bildschirm: kürzere Fassung
        titel = "SUBNETTING MEISTER 2026"
        untertitel = "IPv4 · VLSM · IPv6"
    print(c("╔" + "═" * (w - 2) + "╗", F.CYAN))
    print(c("║", F.CYAN) + regenbogen(titel.center(w - 2)) + c("║", F.CYAN))
    for teil in umbrechen(untertitel, w - 4, 1):
        print(c("║", F.CYAN) + c(teil.strip().center(w - 2), F.GRAU) + c("║", F.CYAN))
    print(c("╚" + "═" * (w - 2) + "╝", F.CYAN))
    pause(0.2)


def menue_zeigen() -> None:
    print("")
    for nr, text, _ in MENUE:
        drucke(f"  {c(nr.rjust(2), F.GELB, F.FETT)}  {text}", 6)      # rjust(2): "9" und "10" stehen bündig


def main() -> None:
    # 1) Argumente aus dem Terminal lesen (z. B. subnetear 10.0.0.0/24 -n 4)
    try:
        args = baue_parser().parse_args()
    except EingabeFehler as fehler:
        drucke(c(f"\n  ✘ {fehler}", F.ROT, F.FETT), 4)
        sys.exit(2)

    if args.hilfe:
        zeige_hilfe()
        return

    # 2) Wurde etwas außer --ohne-animation angegeben? Dann direkt rechnen, ohne Menü.
    if args.cidr or args.ziel or args.python or args.vlsm or args.speichern or args.anzahl is not None:
        try:
            cli_ausfuehren(args)
        except EingabeFehler as fehler:
            drucke(c(f"\n  ✘ {fehler}", F.ROT, F.FETT), 4)
            sys.exit(1)
        except (EOFError, KeyboardInterrupt):
            print(c("\n  (abgebrochen)", F.GRAU))
        finally:
            VORGABEN.clear()                      # nichts Übriges liegen lassen
        return

    # 3) Sonst: das interaktive Menü wie bisher
    banner()
    aktionen = {nr: fkt for nr, _, fkt in MENUE}
    while True:
        menue_zeigen()
        try:
            wahl = input(c("\n➤ Deine Wahl: ", F.GRUEN, F.FETT)).strip()
        except (EOFError, KeyboardInterrupt):
            wahl = "0"
        if wahl == "0":
            drucke("")
            drucke(c("Bis bald – Schritt für Schritt wird Subnetting leicht. 🌱", F.CYAN, F.FETT), 2)
            drucke("")
            return
        if wahl not in aktionen:
            print(c("  Bitte eine Zahl aus dem Menü wählen.", F.ROT))
            continue
        try:
            aktionen[wahl]()
        except EingabeFehler as fehler:
            drucke(c(f"\n  ✘ {fehler}", F.ROT, F.FETT), 4)
        except (EOFError, KeyboardInterrupt):
            print(c("\n  (abgebrochen – zurück zum Menü)", F.GRAU))
        input(c("\n  [Enter] zurück zum Menü ", F.GRAU))


if __name__ == "__main__":
    main()
