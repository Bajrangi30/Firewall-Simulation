# GUI.py (Updated) - append-only logs for user actions, no background auto-traffic
import customtkinter as ctk
from tkinter import ttk, messagebox, filedialog
import threading, time, random, os, json, platform, csv, datetime
from firewall import Firewall

# Try import matplotlib; if missing, disable chart features
HAS_MPL = True
try:
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
except Exception:
    HAS_MPL = False

# sound helper
def play_alert():
    try:
        if platform.system() == "Windows":
            import winsound
            winsound.MessageBeep(winsound.MB_ICONHAND)
        else:
            print("\a", end="", flush=True)
    except Exception:
        pass

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

fw = Firewall()

class AdvancedGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Firewall Simulation Model - Full Advanced (Logs = user actions)")
        self.geometry("1200x760")
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.allowed = 0
        self.blocked = 0
        self.running = True

        # layout frames
        left = ctk.CTkFrame(self, width=350)
        left.pack(side="left", fill="y", padx=12, pady=12)
        right = ctk.CTkFrame(self)
        right.pack(side="right", fill="both", expand=True, padx=12, pady=12)

        # Left: Rule editor & attack sim
        ctk.CTkLabel(left, text="Add Firewall Rule", font=("Arial", 16, "bold")).pack(pady=(6,8))

        self.src_e = ctk.CTkEntry(left, placeholder_text="Source IP (or *)")
        self.src_e.pack(padx=8, pady=6)
        self.dst_e = ctk.CTkEntry(left, placeholder_text="Destination IP (or *)")
        self.dst_e.pack(padx=8, pady=6)
        self.port_e = ctk.CTkEntry(left, placeholder_text="Port (80,443,*)")
        self.port_e.pack(padx=8, pady=6)

        self.proto_cb = ctk.CTkComboBox(left, values=["TCP","UDP","HTTP","HTTPS","*"])
        self.proto_cb.set("*")
        self.proto_cb.pack(padx=8, pady=6)

        self.action_cb = ctk.CTkComboBox(left, values=["allow","deny"])
        self.action_cb.set("deny")
        self.action_cb.pack(padx=8, pady=6)

        self.comment_e = ctk.CTkEntry(left, placeholder_text="Comment (optional)")
        self.comment_e.pack(padx=8, pady=6)

        btn_frame = ctk.CTkFrame(left)
        btn_frame.pack(pady=8)
        ctk.CTkButton(btn_frame, text="Add Rule (Top)", command=self.add_rule).grid(row=0,column=0,padx=6)
        ctk.CTkButton(btn_frame, text="Reload Rules", command=self.load_rules).grid(row=0,column=1,padx=6)

        # rule list with move up/down and remove
        ctk.CTkLabel(left, text="Rules (top → priority)", font=("Arial", 12)).pack(pady=(10,2))
        cols = ("IP","Port","Proto","Action","Comment")
        self.tree = ttk.Treeview(left, columns=cols, show="headings", height=8)
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=60 if c!="Comment" else 120, anchor="center")
        self.tree.pack(padx=6, pady=6)

        rule_ops = ctk.CTkFrame(left)
        rule_ops.pack(pady=6)
        ctk.CTkButton(rule_ops, text="Move Up", command=self.move_up).grid(row=0,column=0,padx=6)
        ctk.CTkButton(rule_ops, text="Move Down", command=self.move_down).grid(row=0,column=1,padx=6)
        ctk.CTkButton(rule_ops, text="Remove", command=self.remove_selected).grid(row=0,column=2,padx=6)
        ctk.CTkButton(rule_ops, text="Clear All", command=self.clear_rules).grid(row=0,column=3,padx=6)

        # Attack Simulation
        ctk.CTkLabel(left, text="Attack Simulations", font=("Arial", 14, "bold")).pack(pady=(12,6))
        ctk.CTkButton(left, text="Port Scan", command=self.port_scan).pack(fill="x", padx=12, pady=4)
        ctk.CTkButton(left, text="Brute Force", command=self.brute_force).pack(fill="x", padx=12, pady=4)
        ctk.CTkButton(left, text="DDoS Sim", command=self.ddos_sim).pack(fill="x", padx=12, pady=4)

        # Export & search
        ctk.CTkLabel(left, text="Export / Search", font=("Arial", 12, "bold")).pack(pady=(12,6))
        ctk.CTkButton(left, text="Export Logs (CSV)", command=self.export_logs_csv).pack(fill="x", padx=12, pady=6)
        ctk.CTkButton(left, text="Export Logs (JSON)", command=self.export_logs_json).pack(fill="x", padx=12, pady=6)
        ctk.CTkButton(left, text="Export Rules (JSON)", command=self.export_rules).pack(fill="x", padx=12, pady=6)

        ctk.CTkLabel(left, text="Search Logs (IP/Port/Protocol):").pack(pady=(8,2))
        self.search_e = ctk.CTkEntry(left, placeholder_text="search text")
        self.search_e.pack(padx=12, pady=6)
        ctk.CTkButton(left, text="Search Logs", command=self.search_logs).pack(padx=12, pady=6)

        # Right: Top - simulate, animation; Bottom - chart + logs
        top_right = ctk.CTkFrame(right)
        top_right.pack(fill="x", pady=(6,10))

        sim_frame = ctk.CTkFrame(top_right)
        sim_frame.pack(fill="x", padx=6, pady=4)

        ctk.CTkLabel(sim_frame, text="Source IP:").grid(row=0,column=0,padx=6,pady=6)
        self.sip = ctk.CTkEntry(sim_frame, width=140); self.sip.grid(row=0,column=1)
        self.sip.insert(0,"192.168.1.100")

        ctk.CTkLabel(sim_frame, text="Port:").grid(row=0,column=2,padx=6,pady=6)
        self.sport = ctk.CTkEntry(sim_frame, width=80); self.sport.grid(row=0,column=3)
        self.sport.insert(0,"80")

        ctk.CTkLabel(sim_frame, text="Protocol:").grid(row=0,column=4,padx=6,pady=6)
        self.sproto = ctk.CTkComboBox(sim_frame, values=["TCP","UDP","HTTP","HTTPS"], width=120); self.sproto.grid(row=0,column=5)
        self.sproto.set("TCP")

        ctk.CTkButton(sim_frame, text="Simulate Packet", command=self.simulate_packet).grid(row=0,column=6,padx=8)
        ctk.CTkButton(sim_frame, text="Random Packet", command=self.random_packet).grid(row=0,column=7,padx=4)

        # animation canvas
        anim_frame = ctk.CTkFrame(right)
        anim_frame.pack(fill="x", padx=6, pady=6)
        self.canvas = ctk.CTkCanvas(anim_frame, width=780, height=160, bg="#0b0f15", highlightthickness=0)
        self.canvas.pack(padx=6, pady=6)
        self._draw_nodes()

        # bottom frame: chart left, logs right
        bottom = ctk.CTkFrame(right)
        bottom.pack(fill="both", expand=True, padx=6, pady=6)

        chart_frame = ctk.CTkFrame(bottom)
        chart_frame.pack(side="left", fill="both", expand=True, padx=(6,3), pady=6)

        logs_frame = ctk.CTkFrame(bottom)
        logs_frame.pack(side="right", fill="both", expand=True, padx=(3,6), pady=6)

        # Chart area (matplotlib if present)
        if HAS_MPL:
            self.fig = Figure(figsize=(4,2))
            self.ax = self.fig.add_subplot(111)
            self.canvas_fig = FigureCanvasTkAgg(self.fig, master=chart_frame)
            self.canvas_fig.get_tk_widget().pack(fill="both", expand=True, padx=6, pady=6)
        else:
            ctk.CTkLabel(chart_frame, text="Matplotlib not installed.\nInstall matplotlib for live charts.", justify="center").pack(expand=True, padx=10, pady=10)

        # logs area (this will show only user-performed actions appended)
        ctk.CTkLabel(logs_frame, text="Firewall Logs (user actions)", font=("Arial", 12, "bold")).pack(anchor="w", padx=6, pady=6)
        self.log_text = ctk.CTkTextbox(logs_frame)
        self.log_text.pack(fill="both", expand=True, padx=6, pady=6)
        log_ops = ctk.CTkFrame(logs_frame)
        log_ops.pack(pady=6)
        ctk.CTkButton(log_ops, text="Refresh Logs (file)", command=self.refresh_logs).pack(side="left", padx=6)
        ctk.CTkButton(log_ops, text="Clear Logs", command=self.clear_logs).pack(side="left", padx=6)

        # load UI data
        self.load_rules()
        self.refresh_logs()  # load existing logs if you want

        # show initial chart
        self.update_chart()

        # NOTE: background fake traffic thread REMOVED intentionally.
        # All logs now appear only when user performs actions.

    # ---- UI helpers ----
    def _draw_nodes(self):
        self.canvas.delete("all")
        # labels + circles
        self.canvas.create_text(120,30, text="SOURCE", fill="#cbd5e1", font=("Arial", 12))
        self.canvas.create_text(390,30, text="FIREWALL", fill="#cbd5e1", font=("Arial", 12))
        self.canvas.create_text(660,30, text="DESTINATION", fill="#cbd5e1", font=("Arial", 12))
        self.canvas.create_oval(80,50,160,130, fill="#1e293b", outline="#60a5fa", width=3)
        self.canvas.create_oval(350,50,430,130, fill="#1f2937", outline="#fb923c", width=3)
        self.canvas.create_oval(620,50,700,130, fill="#0f172a", outline="#34d399", width=3)

    def add_rule(self):
        ip = self.src_e.get().strip() or "*"
        port = self.port_e.get().strip() or "*"
        proto = (self.proto_cb.get() or "*").upper()
        action = (self.action_cb.get() or "deny").lower()
        comment = self.comment_e.get().strip()
        fw.add_rule(ip, port, proto, action, comment)
        self.load_rules()
        messagebox.showinfo("Rule", "Rule added (top priority).")
        # append to GUI logs (user action)
        self.append_log(f"[RULE ADDED] ip={ip} port={port} proto={proto} action={action} comment={comment}")

    def load_rules(self):
        fw.load_rules()
        # populate tree
        for i in self.tree.get_children():
            self.tree.delete(i)
        for r in fw.rules:
            self.tree.insert("", "end", values=(r.get("ip","*"), r.get("port","*"), r.get("protocol","*"), r.get("action","*"), r.get("comment","")))

    def remove_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Select", "Select a rule to remove.")
            return
        idx = self.tree.index(sel[0])
        if fw.remove_rule(idx):
            self.load_rules()
            messagebox.showinfo("Removed", "Rule removed.")
            self.append_log(f"[RULE REMOVED] index={idx}")

    def move_up(self):
        sel = self.tree.selection()
        if not sel: return
        idx = self.tree.index(sel[0])
        if fw.move_rule_up(idx):
            self.load_rules()
            self.append_log(f"[RULE MOVED UP] index={idx}")

    def move_down(self):
        sel = self.tree.selection()
        if not sel: return
        idx = self.tree.index(sel[0])
        if fw.move_rule_down(idx):
            self.load_rules()
            self.append_log(f"[RULE MOVED DOWN] index={idx}")

    def clear_rules(self):
        if messagebox.askyesno("Confirm", "Clear all rules?"):
            fw.clear_rules()
            self.load_rules()
            self.append_log("[RULES CLEARED]")

    # ---- simulate + animation ----
    def simulate_packet(self):
        pkt = {"ip": self.sip.get().strip(), "port": self.sport.get().strip(), "protocol": self.sproto.get().strip().upper()}
        if not pkt["ip"] or not pkt["port"] or not pkt["protocol"]:
            messagebox.showwarning("Input", "Please fill all fields.")
            return
        # run packet handling in separate thread to keep UI responsive
        threading.Thread(target=self._handle_packet_and_log, args=(pkt,), daemon=True).start()

    def _handle_packet_and_log(self, pkt):
        # call firewall engine
        res = fw.check_packet(pkt)  # firewall already logs to logs.txt internally
        # update counts
        if res == "allow":
            self.allowed += 1
            action_text = "ALLOW"
        else:
            self.blocked += 1
            action_text = "BLOCK"
            play_alert()
        # update chart
        self.update_chart()
        # animate packet visually
        self._animate_packet(res)
        # append readable log to GUI and also write to logs file (fw.log_event already wrote, but we add a friendly line too)
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{now}] [PACKET] {pkt['ip']}:{pkt['port']} ({pkt['protocol']}) => {action_text}"
        self.append_log(line)

    def random_packet(self):
        pkt = fw.generate_fake_packet()
        self.sip.delete(0,"end"); self.sip.insert(0,pkt["ip"])
        self.sport.delete(0,"end"); self.sport.insert(0,pkt["port"])
        self.sproto.set(pkt["protocol"])
        # treat as user action (not background)
        self.simulate_packet()

    def _animate_packet(self, action):
        self._draw_nodes()
        color = "#34d399" if action=="allow" else "#fb7185"
        pkt = self.canvas.create_oval(100,140,120,160, fill=color, outline="")
        for x in range(100,660,10):
            self.canvas.coords(pkt, x,140, x+20,160)
            self.update()
            time.sleep(0.015)
            if action=="deny" and x>=360:
                break
        if action=="deny":
            for _ in range(3):
                self.canvas.itemconfig(pkt, fill="#ffffff")
                self.update(); time.sleep(0.07)
                self.canvas.itemconfig(pkt, fill=color)
                self.update(); time.sleep(0.07)
        time.sleep(0.12)
        self.canvas.delete(pkt)

    # ---- fake traffic / attack sims (these append to logs as user actions) ----
    def port_scan(self):
        threading.Thread(target=self._port_scan_run, daemon=True).start()
    def _port_scan_run(self):
        self.append_log("[PORT SCAN] Started")
        results = []
        for p in ["21","22","23","80","443","3306","8080"]:
            pkt = {"ip":"192.168.10.5","port":p,"protocol":"TCP"}
            res = fw.check_packet(pkt)
            status = "ALLOW" if res=="allow" else "BLOCK"
            results.append((p, status))
            # append each port result as user action
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.append_log(f"[{now}] [PORT] port={p} => {status}")
            time.sleep(0.12)
        self.append_log("[PORT SCAN] Completed")

    def brute_force(self):
        threading.Thread(target=self._brute_run, daemon=True).start()
    def _brute_run(self):
        attacker = f"192.168.77.{random.randint(2,200)}"
        self.append_log(f"[BRUTE FORCE] Simulating attacker {attacker}")
        for i in range(8):
            pkt = {"ip":attacker,"port":"22","protocol":"TCP"}
            res = fw.check_packet(pkt)
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            status = "ALLOW" if res=="allow" else "BLOCK"
            self.append_log(f"[{now}] [BRUTE] attempt {i+1} from {attacker} => {status}")
            time.sleep(0.08)
        fw.add_rule(attacker, "*", "*", "deny", "Auto-block - brute force")
        self.load_rules()
        self.append_log(f"[BRUTE FORCE] Completed - {attacker} auto-blocked")

    def ddos_sim(self):
        threading.Thread(target=self._ddos_run, daemon=True).start()
    def _ddos_run(self):
        attacker = f"203.0.113.{random.randint(2,200)}"
        self.append_log(f"[DDOS] Simulating flood from {attacker}")
        for i in range(35):
            pkt = {"ip":attacker,"port":"80","protocol":"HTTP"}
            res = fw.check_packet(pkt)
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            status = "ALLOW" if res=="allow" else "BLOCK"
            # append summary lines occasionally to avoid flooding UI too fast
            if i % 5 == 0:
                self.append_log(f"[{now}] [DDOS] packet {i+1} => {status}")
            time.sleep(0.06)
        fw.add_rule(attacker, "*", "*", "deny", "Auto-block - DDoS")
        self.load_rules()
        self.append_log(f"[DDOS] Completed - {attacker} auto-blocked")

    # ---- logging helpers ----
    def append_log(self, text):
        """
        Append a user-action log line to GUI and also write to logs file via fw.log_event
        """
        try:
            # write to logs file (fw.log_event adds timestamp)
            # we pass plain text (without timestamp) to fw.log_event so file will have timestamp
            # but in GUI we show a readable line with timestamp included (if not present)
            # determine if text already has timestamp (starts with '[')
            if text.startswith("[") and "]" in text:
                # attempt to split timestamp out for fw.log_event
                # but to keep it simple: write the raw text to GUI and call fw.log_event with text
                fw.log_event(text)
            else:
                fw.log_event(text)
            # display in GUI - keep exactly the provided text (user-friendly)
            self.log_text.configure(state="normal")
            self.log_text.insert("end", text + "\n")
            self.log_text.see("end")
            self.log_text.configure(state="disabled")
        except Exception as e:
            print("append_log error:", e)

    def refresh_logs(self):
        """
        Load the full logs file into the GUI text box (useful if you want to view entire file).
        Note: append_log already shows user actions live, this is for loading full file.
        """
        try:
            txt = fw.read_logs(10000)
            # optional search filter
            s = self.search_e.get().strip()
            if s:
                lines = [l for l in txt.splitlines() if s.lower() in l.lower()]
                display = "\n".join(lines)
            else:
                display = txt
            self.log_text.configure(state="normal")
            self.log_text.delete("1.0","end")
            self.log_text.insert("end", display)
            self.log_text.see("end")
            self.log_text.configure(state="disabled")
        except Exception as e:
            messagebox.showerror("Error", f"Could not read logs: {e}")

    def clear_logs(self):
        if messagebox.askyesno("Confirm", "Clear logs file?"):
            open("logs.txt","w").close()
            self.log_text.configure(state="normal")
            self.log_text.delete("1.0","end")
            self.log_text.configure(state="disabled")
            fw.log_event("[LOGS CLEARED]")
            self.append_log("[LOGS CLEARED]")

    def search_logs(self):
        self.refresh_logs()

    def export_logs_csv(self):
        txt = fw.read_logs(10000)
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files","*.csv")])
        if not path: return
        try:
            with open(path, "w", newline='', encoding="utf-8") as csvf:
                writer = csv.writer(csvf)
                writer.writerow(["Timestamp","Event"])
                for line in txt.splitlines():
                    if line.strip():
                        if line.startswith("["):
                            try:
                                ts, rest = line.split("]",1)
                                writer.writerow([ts.strip("["), rest.strip()])
                            except:
                                writer.writerow(["", line])
                        else:
                            writer.writerow(["", line])
            messagebox.showinfo("Export", f"Logs exported to {path}")
            self.append_log(f"[EXPORT] Logs exported to {path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def export_logs_json(self):
        txt = fw.read_logs(10000)
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files","*.json")])
        if not path: return
        try:
            out = []
            for line in txt.splitlines():
                if line.strip():
                    out.append({"line": line})
            with open(path, "w", encoding="utf-8") as f:
                json.dump(out, f, indent=2)
            messagebox.showinfo("Export", f"Logs exported to {path}")
            self.append_log(f"[EXPORT] Logs exported to {path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def export_rules(self):
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files","*.json")])
        if not path: return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"rules": fw.rules}, f, indent=2)
            messagebox.showinfo("Export", f"Rules exported to {path}")
            self.append_log(f"[EXPORT] Rules exported to {path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ---- chart ----
    def update_chart(self):
        if not HAS_MPL:
            return
        try:
            self.ax.clear()
            labels = ["Allowed","Blocked"]
            values = [self.allowed, self.blocked]
            colors = ["#34d399","#fb7185"]
            self.ax.bar(labels, values, color=colors)
            self.ax.set_ylim(0, max(5, self.allowed+self.blocked+1))
            self.ax.set_title("Traffic: Allowed vs Blocked")
            self.canvas_fig.draw()
        except Exception:
            pass

    # ---- closing ----
    def on_close(self):
        self.running = False
        time.sleep(0.2)
        self.destroy()

if __name__ == "__main__":
    app = AdvancedGUI()
    app.mainloop()
