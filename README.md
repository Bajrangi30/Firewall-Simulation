# Network Firewall Simulation Model

**Author:** Bajrangi Yadav  
**Course:** B.Tech CSE (Cyber Security)

---

## Project Overview
This is a Python-based **Firewall Simulation Model** with GUI.  
It allows users to add firewall rules, simulate packets, visualize packet flow, see real-time logs, and view live traffic statistics.

---

## Features
- Add / Remove firewall rules (IP, Port, Protocol, Allow/Deny)
- Simulate single packets (manual input)
- Real-time fake traffic generator (auto packets)
- Animated packet flow visualization
- Live traffic graph (Allowed vs Blocked)
- Auto-block suspicious IP after multiple denies
- Logs saved to `logs.txt` (timestamped)
- Simple attack simulations (Port scan / DDoS / Brute force)
- Works on Windows / Linux (Tkinter included with Python)

---

## Requirements
- Python 3.8+  
- Packages:
  - `customtkinter`
  - `matplotlib`

Install via:
```bash
python -m pip install customtkinter matplotlib
