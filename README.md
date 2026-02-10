# subnetting
## IPv4 Subnetting Helper (for LPIC / IHK / CompTIA students)

**Note (February 2025):** This is a small Python tool I built while studying for networking certifications in Germany.  
I'm not a professional developer — just someone who needed a fast way to calculate subnets, magic numbers, interesting octets, and host ranges without always pulling out a calculator or Excel.

It was created with a lot of trial-and-error + help from modern AI tools.  
So please don't expect a super polished production-grade program — but it has helped me (and hopefully can help others too).

---

## What it does

- Split a network into **N subnets**
- Split to a **target prefix length** (`/xx`)
- Calculate subnets based on **required usable hosts per subnet**
- Find which **subnet an IP address belongs to**
- Analyze any single IPv4 network (`/0` to `/32`, with correct `/31` and `/32` handling)

### It shows

- Magic number
- Interesting octet
- Wildcard mask
- First/last usable host
- Export to **Markdown + CSV** (useful for Berichtsheft / documentation)

---

## Installation (Fedora / Linux)

### Option 1: Clone with Git
```bash
git clone https://github.com/utopiasinfin/subnetting.git
cd subnetting

# subnetting

Script en Python para practicar/automatizar subnetting IPv4.

## Requisitos

- Python 3

## Ejecutar (Fedora / Linux)
```bash
python3 src/subnetear.py
```
