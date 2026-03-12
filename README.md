IPv4 Subnetting Helper (for LPIC / IHK / CompTIA students)

Note (February 2026):

This is a small Python tool I created while studying networking for certifications such as LPIC, IHK, and CompTIA.

I'm not a professional Python developer. The idea for this tool came from my own need to better understand subnetting concepts such as subnet masks, interesting octets, magic numbers, and host ranges without always relying on a calculator or spreadsheet.

The program was developed with the help of modern AI tools, combined with a lot of trial-and-error while learning. I used the process not only to build the tool, but also to deepen my understanding of networking concepts and basic programming logic.

So this is not meant to be a polished production-grade application. It is mainly a learning project — and a practical helper that made studying subnetting much easier for me.

If it helps other students who are learning networking, then the project has achieved its goal.

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
