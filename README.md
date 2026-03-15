# Subnetting Tutor 🧮

**An educational CLI tool for learning IPv4 and IPv6 subnetting**

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-brightgreen)

## 📚 Purpose

**Subnetting Tutor** is an interactive command-line tool designed to help students, network administrators, and IT professionals **understand and practice subnetting** through step-by-step explanations.

Unlike simple subnet calculators that just give you the answer, this tool **teaches you HOW and WHY** subnetting works. Every calculation includes detailed explanations of the underlying mechanisms.

## 🎯 What It Teaches

- **IPv4 Subnetting** - The fundamentals of CIDR notation, network masks, and host calculations
- **IPv6 Subnetting** - Understanding IPv6 prefixes and subnet allocation
- **VLSM** - Variable Length Subnet Masking for efficient address allocation
- **Binary Operations** - Visual representation of IP addresses in binary
- **Magic Number** - Understanding subnet jumping and network boundaries
- **Practical Skills** - Real-world scenarios for network design

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Step-by-Step Explanations** | Every calculation shows the complete process, not just the result |
| **Binary Visualization** | See IP addresses and masks in binary to understand bit operations |
| **Learning Mode** | Detailed explanations of concepts like borrowed bits, host bits, magic number |
| **Quiz Mode** | Test your knowledge with random questions |
| **VLSM Calculator** | Design efficient networks with variable-sized subnets |
| **IPv6 Support** | Full IPv6 subnetting capabilities |
| **Export** | Save results to CSV and Markdown for documentation |
| **Multilingual Tips** | German explanations (can be extended) |

## 🚀 Quick Start

```bash
# Clone or download the program
cd subnetear.py

# Run the program
python3 subnetear.py

# Or without colors (better for some terminals)
python3 subnetear.py --no-color
```

## 📖 Usage

### Menu Options

```
1) Split network into N subnets       - Learn: How to divide a network
2) Split by target prefix /xx         - Learn: Understanding /xx notation  
3) Split by hosts per subnet         - Learn: Host capacity calculations
4) IP → Subnet lookup                - Learn: Finding where an IP belongs
5) Analyze a subnet                  - Learn: Network/broadcast/hosts
6) IPv6 subnet analysis              - Learn: IPv6 prefixes
7) IPv6 network division             - Learn: IPv6 subnetting
8) Quiz mode                         - Test your knowledge
9) VLSM calculator                   - Learn: Variable length subnets
0) Exit
```

### Example: Splitting a Network

```
Menu: 1

Ausgangsnetz (z.B. 192.168.1.0/24): 192.168.1.0/24
Wie viele Subnetze brauchst du? 8

🎓 LERNEN: Wie funktioniert Subnetting?
   Subnetting = Netz in kleinere Stücke teilen
   Wir 'borgen' Bits von den Host-Bits für neue Subnetze

🧮 Schritt 1: Berechne benötigte Bits
   Du willst 8 Subnetze.
   Frage: 2^wieviele Bits ≥ 8?
   Merke: Jedes Bit verdoppelt die Anzahl!
   2^1 = 2, 2^2 = 4, 2^3 = 8, 2^4 = 16, ...

🧮 Schritt 2: Die Formel
   Formel: borrowed_bits = ceil(log2(8))
   Neues Präfix = altes Präfix + borrowed_bits
                 = /24 + 3
                 = /27

✅ Ergebnis: 8 Subnetze
   - 192.168.1.0/27    (30 hosts)
   - 192.168.1.32/27   (30 hosts)
   - 192.168.1.64/27   (30 hosts)
   ...
```

## 🧮 Key Concepts Explained

### The Magic Number

The **Magic Number** is the key to quick subnet calculations:

```
For /27: Magic = 256 - 224 = 32
Network addresses: 0, 32, 64, 96, 128, ...
```

### Borrowed Bits Formula

```
Anzahl Subnetze = 2^(borrowed bits)
Hosts pro Subnetz = 2^(host bits) - 2
```

### Binary Understanding

```
IP:       192.168.1.100
Binary:   11000000.10101000.00000001.01100100
Mask:     255.255.255.224 (/27)
Binary:   11111111.11111111.11111111.11100000
                              ↑↑↑↑↑
                          These 5 bits are for hosts
```

## 📝 Requirements

- Python 3.10+
- No external dependencies (uses standard library only)

## 🔧 Installation

```bash
# Make it executable
chmod +x subnetear.py

# Run directly
./subnetear.py

# Or with Python
python3 subnetear.py
```

## 📂 Output Files

After calculations, you can export results:

- **CSV** - For spreadsheet analysis
- **Markdown** - For documentation

Files are saved to `~/Downloads/` by default.

## 🎓 Educational Value

This program is perfect for:

- **CompTIA Network+** exam preparation
- **CCNA** subnetting practice  
- **IHK (German IT exams)** preparation
- **LPIC** certification studies
- **Self-learning** network fundamentals

## 🤝 Credits

**Idea & Concept:** Wilson (utopiasinfin)  
**Development:** opencode AI Assistant  

Created as a learning tool to make subnetting accessible and understandable for everyone.

## 📜 License

MIT License - Feel free to use, modify, and share!

---

*Remember: The key to understanding subnetting is practice. Use this tool to experiment and learn!* 🎉
