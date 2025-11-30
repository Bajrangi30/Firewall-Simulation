


## 3) `firewall.py`

import json
import datetime
from pathlib import Path

RULES_FILE = "rules.json"
LOG_FILE = "logs.txt"

class Firewall:
    def __init__(self):
        self.rules = []
        self.log_file = LOG_FILE
        self.load_rules()
        # track denies per IP for auto-block
        self.deny_counts = {}

    def load_rules(self):
        p = Path(RULES_FILE)
        if not p.exists():
            default = {
                "rules": [
                    {"ip":"*", "port":"23", "protocol":"TCP", "action":"deny", "comment":"Block Telnet"},
                    {"ip":"192.168.1.50", "port":"80", "protocol":"TCP", "action":"allow", "comment":"Local web"}
                ]
            }
            with open(RULES_FILE, "w") as f:
                json.dump(default, f, indent=4)
            self.rules = default["rules"]
        else:
            try:
                with open(RULES_FILE, "r") as f:
                    data = json.load(f)
                if isinstance(data, dict) and "rules" in data:
                    self.rules = data["rules"]
                elif isinstance(data, list):
                    self.rules = data
                else:
                    self.rules = []
            except Exception as e:
                print("Error load rules:", e)
                self.rules = []

    def save_rules(self):
        try:
            with open(RULES_FILE, "w") as f:
                json.dump({"rules": self.rules}, f, indent=4)
        except Exception as e:
            print("Error save rules:", e)

    def add_rule(self, ip="*", port="*", protocol="*", action="deny", comment=""):
        rule = {"ip":ip, "port":str(port), "protocol":protocol.upper(), "action":action.lower(), "comment":comment}
        # insert on top (higher priority)
        self.rules.insert(0, rule)
        self.save_rules()
        self.log_event(f"[RULE ADDED] {rule}")

    def remove_rule(self, index):
        try:
            removed = self.rules.pop(index)
            self.save_rules()
            self.log_event(f"[RULE REMOVED] {removed}")
            return True
        except Exception:
            return False

    def move_rule_up(self, index):
        if 0 < index < len(self.rules):
            self.rules[index-1], self.rules[index] = self.rules[index], self.rules[index-1]
            self.save_rules()
            return True
        return False

    def move_rule_down(self, index):
        if 0 <= index < len(self.rules)-1:
            self.rules[index+1], self.rules[index] = self.rules[index], self.rules[index+1]
            self.save_rules()
            return True
        return False

    def clear_rules(self):
        self.rules = []
        self.save_rules()
        self.log_event("[RULES CLEARED]")

    def check_packet(self, packet):
        # packet: {"ip":..., "port":..., "protocol":...}
        for rule in self.rules:
            ip_match = (rule["ip"] == "*" or rule["ip"] == packet["ip"])
            port_match = (rule["port"] == "*" or rule["port"] == str(packet["port"]))
            proto_match = (rule["protocol"] == "*" or rule["protocol"].upper() == packet["protocol"].upper())
            if ip_match and port_match and proto_match:
                action = rule["action"]
                self.log_event(f"[PACKET] {packet} => {action.upper()} (matched)")
                # if deny: record for auto-block
                if action.lower() == "deny":
                    self.deny_counts[packet["ip"]] = self.deny_counts.get(packet["ip"],0) + 1
                    if self.deny_counts[packet["ip"]] >= 6:
                        # auto-block after threshold
                        self.add_rule(packet["ip"], "*", "*", "deny", "Auto-block after repeated denies")
                return action
        self.log_event(f"[PACKET] {packet} => ALLOW (default)")
        # reset deny count for that ip on allow
        self.deny_counts.pop(packet["ip"], None)
        return "allow"

    def log_event(self, text):
        t = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{t}] {text}\n"
        try:
            with open(self.log_file, "a") as f:
                f.write(line)
        except Exception as e:
            print("Log write error:", e)

    def read_logs(self, tail_lines=1000):
        try:
            with open(self.log_file, "r") as f:
                lines = f.readlines()
            if tail_lines and len(lines) > tail_lines:
                return "".join(lines[-tail_lines:])
            return "".join(lines)
        except FileNotFoundError:
            return ""
        except Exception as e:
            return f"Error reading logs: {e}"

    def generate_fake_packet(self):
        import random
        proto = random.choice(["TCP","UDP","HTTP","HTTPS"])
        port_map = {"HTTP":80,"HTTPS":443}
        if proto in port_map and random.random() > 0.4:
            port = port_map[proto]
        else:
            port = random.choice([22,23,53,80,443,8080])
        return {"ip":f"192.168.1.{random.randint(2,254)}", "port":str(port), "protocol":proto}
