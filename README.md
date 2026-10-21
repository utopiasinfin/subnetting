# Subnetting-Meister 🧮

**Subnetting lernen, verstehen und rechnen – im Terminal, auf jedem Gerät.**

Dieses Repository enthält zwei Werkzeuge für IPv4- und IPv6-Subnetting:

| Programm | Datei | Einschätzung |
|---|---|---|
| **Subnetting-Meister** (neu) | `subnetting_meister.py` | ⭐ **Das Hauptprogramm, empfohlen** |
| Subnetting Tutor (Vorgänger) | `src/subnetear.py` | Das erste Tool, bleibt als Lernbeispiel erhalten |

Entstanden sind sie beim Lernen für die **Systemintegration**: Ich wollte ein Werkzeug, das nicht nur das Ergebnis zeigt, sondern **erklärt, warum es so ist**.

---

## ⭐ Subnetting-Meister (neu)

Der Subnetting-Meister rechnet jede Aufgabe Schritt für Schritt vor. Zu jedem Schritt gibt es drei Antworten: **Warum** ist das so, **Wie** rechnet man es, **Wozu** braucht man es im Alltag.

### Was kann er?

- **IP-Analyse** in 7 Schritten, mit farbiger Binärdarstellung (Netzanteil und Hostanteil sind getrennt eingefärbt)
- **Netz teilen** nach Anzahl der Subnetze oder nach Ziel-Präfix
- **VLSM** für Subnetze unterschiedlicher Größe, mit Anzeige der freien Reste
- **Gleiches Netz?** Prüft, ob zwei Hosts ohne Router miteinander reden können
- **Merkzahl-Methode** zum Kopfrechnen ohne Binär, wie in der Prüfung
- **IPv6:** Grundlagen, Adressen analysieren, Netze in /64 teilen
- **Spickzettel** mit Präfix-Tabelle, privaten Adressbereichen, Praxis-Tipps und typischen Fehlern
- **Quiz** im Prüfungsstil, mit Hinweisen
- **Export** der Ergebnisse als `.md` und `.csv`
- **Python-Lernecke:** Der Code des Tools wird Zeile für Zeile erklärt, mit echten Beispielwerten
- **Sonderfälle** wie /31 (RFC 3021) und /32 werden richtig behandelt
- **Passt sich automatisch an jeden Bildschirm an:** Handy, Tablet, Laptop oder SSH. Auf schmalen Bildschirmen werden Tabellen zu übersichtlichen Karten, lange Texte brechen sauber um

### Benutzung

```bash
python3 subnetting_meister.py                        # Menü mit allen Funktionen
python3 subnetting_meister.py 192.168.10.77/26       # Schnellanalyse
python3 subnetting_meister.py 10.0.0.0/24 -n 4       # in 4 Subnetze teilen
python3 subnetting_meister.py 10.0.0.0/24 /27        # in lauter /27 teilen
python3 subnetting_meister.py 192.168.0.0/24 --vlsm 100,50,20,2
python3 subnetting_meister.py 2001:db8:abcd::/48 /64 # IPv6 teilen
python3 subnetting_meister.py --python               # Python-Lernecke
python3 subnetting_meister.py --hilfe                # alle Optionen
```

Beispiel (VLSM mit Bedarf 100, 50, 20 und 2 Hosts):

```
  Nr  Bedarf  Netz                Erster Host     Letzter Host    Broadcast       Frei
  ──────────────────────────────────────────────────────────────────────────────────
   1     100  192.168.0.0/25      192.168.0.1     192.168.0.126   192.168.0.127     26
   2      50  192.168.0.128/26    192.168.0.129   192.168.0.190   192.168.0.191     12
   3      20  192.168.0.192/27    192.168.0.193   192.168.0.222   192.168.0.223     10
   4       2  192.168.0.224/30    192.168.0.225   192.168.0.226   192.168.0.227      0

  Belegt: 228 von 256 Adressen (89.1 %)
```

### Installation

Reines Python 3.10 oder neuer, **keine zusätzlichen Pakete**.

**Linux:**

```bash
git clone https://github.com/utopiasinfin/subnetting.git
cd subnetting
python3 subnetting_meister.py
```

Optional als Kurzbefehl `subnetear`:

```bash
chmod +x subnetting_meister.py
mkdir -p ~/.local/bin
ln -s "$(pwd)/subnetting_meister.py" ~/.local/bin/subnetear
```

**Android (Termux):**

```bash
pkg install python git
git clone https://github.com/utopiasinfin/subnetting.git
cd subnetting
chmod +x subnetting_meister.py
ln -s "$(pwd)/subnetting_meister.py" $PREFIX/bin/subnetear
```

---

## Subnetting Tutor (Vorgänger)

Der **Subnetting Tutor** (`src/subnetear.py`) war das erste Tool. Er ist ein interaktives Kommandozeilenprogramm, das jede Rechnung erklärt, statt nur das Ergebnis zu liefern. Laut seiner ursprünglichen Beschreibung kann er:

- IPv4- und IPv6-Subnetting mit Erklärungen (CIDR, Masken, Hostberechnung)
- Netze nach Anzahl der Subnetze, nach Ziel-Präfix oder nach Hosts pro Subnetz teilen
- zu einer IP das passende Subnetz finden
- VLSM berechnen
- IP-Adressen und Masken binär darstellen
- die Merkzahl erklären
- ein Quiz anbieten
- Ergebnisse als CSV und Markdown exportieren

Starten:

```bash
python3 src/subnetear.py
```

Er bleibt in diesem Repository, weil er ein guter Ausgangspunkt zum Lernen ist und gezeigt hat, in welche Richtung es gehen soll.

---

## Vergleich

| | Subnetting-Meister (neu) | Subnetting Tutor (Vorgänger) |
|---|:---:|:---:|
| Schrittweise Erklärungen | ✅ | ✅ |
| IPv4, IPv6 und VLSM | ✅ | ✅ |
| Quiz | ✅ | ✅ |
| Export als CSV und Markdown | ✅ | ✅ |
| Befehle direkt im Terminal (ohne Menü) | ✅ | – |
| Anpassung an jede Bildschirmbreite | ✅ | – |
| Gleiches Netz? (Host A ↔ Host B) | ✅ | – |
| Spickzettel mit Praxis-Tipps und typischen Fehlern | ✅ | – |
| Python-Lernecke (Code erklärt) | ✅ | – |
| Sonderfälle /31 und /32 | ✅ | – |

*Die Angaben zum Vorgänger beruhen auf dessen früherer Beschreibung.*

---

## 🤝 Entstehung und Credits

Ich sage es offen, so wie es war:

- **Idee, Anforderungen und Lernziel:** Wilson Escobar Rodriguez (utopiasinfin). Von mir stammt die Idee, dass ein Subnetting-Werkzeug erklären soll, statt nur zu rechnen. Ich habe beide Tools auf meinen eigenen Geräten ausprobiert und mit Rückmeldungen Schritt für Schritt besser gemacht.
- **Subnetting-Meister (neu):** gemeinsam entwickelt mit **Claude** (KI von Anthropic). Den Code hat Claude geschrieben, nach meinen Vorgaben und in ständiger Abstimmung mit mir.
- **Subnetting Tutor (Vorgänger):** gemeinsam entwickelt mit dem **opencode AI Assistant**.

Ich bin kein Berufsentwickler, sondern lerne gerade die Systemintegration. **Meine Idee, gemeinsam umgesetzt.**

## ⚠️ Hinweis

Das sind Lernwerkzeuge und sie kommen ohne Gewähr. Rechne wichtige Ergebnisse in Prüfungen und im Betrieb selbst nach.

## 📜 Lizenz

Siehe die Datei [LICENSE](LICENSE).
