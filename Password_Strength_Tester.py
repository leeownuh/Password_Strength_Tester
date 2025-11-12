#!/usr/bin/env python3
"""
Professional Password Analyzer - All-in-one GUI tool
Save as pro_password_tool.py and run: python pro_password_tool.py
"""

import math
import re
import random
import string
import csv
import time
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


LOWERCASE = r"[a-z]"
UPPERCASE = r"[A-Z]"
DIGITS = r"[0-9]"
SYMBOLS = r"[^a-zA-Z0-9]"

COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123", "111111", "letmein", "admin", "welcome"
}

KEY_SEQS = ["qwerty", "asdf", "zxcv", "12345", "0123456789", "password"]

DEFAULT_POLICY = {
    "min_length": 12,
    "require_upper": True,
    "require_lower": True,
    "require_digits": True,
    "require_symbols": False,
    "disallow_common": True
}

def calculate_entropy(password: str) -> float:
    if not password:
        return 0.0
    charset_size = 0
    if re.search(LOWERCASE, password): charset_size += 26
    if re.search(UPPERCASE, password): charset_size += 26
    if re.search(DIGITS, password): charset_size += 10
    if re.search(SYMBOLS, password): charset_size += 33
    if charset_size == 0:
        # treat as single-symbol set
        return 0.0
    return round(len(password) * math.log2(charset_size), 2)

def classify_strength(entropy: float) -> (str, int):
   
    if entropy < 28:
        return "Very Weak", 15
    elif entropy < 36:
        return "Weak", 30
    elif entropy < 60:
        return "Moderate", 55
    elif entropy < 80:
        return "Strong", 80
    else:
        return "Very Strong", 95

def estimate_crack_time(entropy: float, guesses_per_sec=1e9):
    
    if entropy <= 0:
        return "Instant"
    seconds = 2 ** entropy / guesses_per_sec
    if seconds < 1:
        return f"{round(seconds*1000,2)} ms"
    minute = seconds/60
    if minute < 1:
        return f"{round(seconds,2)} sec"
    hour = minute/60
    if hour < 1:
        return f"{round(minute,2)} min"
    day = hour/24
    if day < 1:
        return f"{round(hour,2)} hr"
    year = day/365
    if year < 1:
        return f"{round(day,2)} days"
    if year < 1000:
        return f"{round(year,2)} years"
    return f">= {round(year,2)} years"

def mask_password(pwd: str) -> str:
    if not pwd: return ""
    if len(pwd) <= 4:
        return "*" * len(pwd)
    return pwd[0] + "*"*(len(pwd)-2) + pwd[-1]


def analyze_patterns(password: str):
    patterns = []
    p = password
    if re.search(r"(.)\1{2,}", p):
        patterns.append("Repeated characters (e.g., aaa or 111)")
    low = p.lower()
    for seq in KEY_SEQS:
        if seq in low:
            patterns.append(f"Common sequence detected: '{seq}'")
            break
    if re.search(r"(19|20)\d{2}", p):
        patterns.append("Year-like sequence detected (e.g., 1990, 2023)")
    if p.lower() in COMMON_PASSWORDS:
        patterns.append("Exact common password found")
    
    if len(p) >= 4 and sum(1 for ch in p.lower() if ch in "qwertyuiopasdfghjklzxcvbnm") >= len(p)*0.7:
        patterns.append("Mostly letters in keyboard order (possible pattern)")
    return patterns

def generate_improvements(password: str, count=5):
    """
    Produce improved password suggestions based on the user's input:
    - Add symbols
    - Insert random characters
    - Leet substitutions
    - Lengthen preserving some original tokens
    """
    suggestions = []
    base = password.strip()
    if not base:
        for _ in range(count):
            suggestions.append(generate_password(length=16, use_symbols=True))
        return suggestions

    
    def leet(s):
        subs = {'a':'@','s':'$','o':'0','i':'1','e':'3','t':'7','l':'1'}
        return ''.join(subs.get(ch.lower(), ch) for ch in s)

    def add_symbols(s):
        sym = random.choice("!@#$%^&*()-_=+[]{};:,.<>?")
        return s + sym + random.choice(string.digits)

    def insert_random(s, n=2):
        pos = random.randrange(0, len(s)+1)
        rnd = ''.join(random.choice(string.ascii_letters + string.digits + "!@#") for _ in range(n))
        return s[:pos] + rnd + s[pos:]

    tokens = re.split(r'(\W+)', base)
    
    tries = 0
    while len(suggestions) < count and tries < count*8:
        tries += 1
        choice = random.choice(['leet','addsym','insert','mix','lengthen'])
        if choice == 'leet':
            cand = leet(base)
        elif choice == 'addsym':
            cand = add_symbols(base)
        elif choice == 'insert':
            cand = insert_random(base, n=random.randint(2,4))
        elif choice == 'mix':
            cand = add_symbols(leet(insert_random(base, n=2)))
        else:
            
            cand = base + random.choice(["!", "@", "#"]) + ''.join(random.choice(string.ascii_letters+string.digits) for _ in range(4))
       
        if len(cand) >= 12 or re.search(SYMBOLS, cand):
            if cand not in suggestions and cand != base:
                suggestions.append(cand)
    
    while len(suggestions) < count:
        suggestions.append(generate_password(length=16, use_symbols=True))
    return suggestions

def generate_password(length=16, use_symbols=True):
    chars = string.ascii_lowercase + string.ascii_uppercase + string.digits
    if use_symbols:
        chars += "!@#$%^&*()-_=+[]{};:,.<>?/\\|"
    return ''.join(random.choice(chars) for _ in range(length))


def check_policy(password: str, policy: dict):
    issues = []
    if len(password) < policy.get("min_length", 12):
        issues.append(f"Too short: minimum {policy.get('min_length')} characters.")
    if policy.get("require_upper") and not re.search(UPPERCASE, password):
        issues.append("Missing uppercase letter.")
    if policy.get("require_lower") and not re.search(LOWERCASE, password):
        issues.append("Missing lowercase letter.")
    if policy.get("require_digits") and not re.search(DIGITS, password):
        issues.append("Missing a digit.")
    if policy.get("require_symbols") and not re.search(SYMBOLS, password):
        issues.append("Missing a symbol.")
    if policy.get("disallow_common") and password.lower() in COMMON_PASSWORDS:
        issues.append("Password is a common password.")
    return issues


class ProPassApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Pro Password Auditor")
        self.root.geometry("980x760")
        self.root.minsize(900,700)
        self.dark = False
        self.session_log = []  
        self.policy = DEFAULT_POLICY.copy()
        self._build_ui()
        self.update_theme()

    def _build_ui(self):
        # === Main window split ===
        top = tk.Frame(self.root)
        top.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        # ==== Scrollable LEFT section ====
        left_container = tk.Frame(top)
        left_container.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        canvas = tk.Canvas(left_container)
        scrollbar = ttk.Scrollbar(left_container, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # ==== RIGHT section ====
        right = tk.Frame(top, width=300)
        right.pack(side=tk.RIGHT, fill=tk.Y, padx=6)

        # Now replace all "left" references below with "scrollable_frame"
        left = scrollable_frame

        # ==== Existing widgets start here ====
        label_title = tk.Label(left, text="PROFESSIONAL PASSWORD ANALYZER", font=("Segoe UI", 16, "bold"))
        label_title.pack(anchor="w")

        entry_frame = tk.Frame(left)
        entry_frame.pack(fill=tk.X, pady=6)
        tk.Label(entry_frame, text="Password:").pack(side=tk.LEFT)
        self.entry = tk.Entry(entry_frame, font=("Segoe UI", 12), show="*", width=36)
        self.entry.pack(side=tk.LEFT, padx=6)
        self.entry.bind("<KeyRelease>", lambda e: self.update_analysis())

        self.toggle_btn = tk.Button(entry_frame, text="Show", width=8, command=self.toggle_show)
        self.toggle_btn.pack(side=tk.LEFT, padx=4)
        copy_btn = tk.Button(entry_frame, text="Copy Results", command=self.copy_results)
        copy_btn.pack(side=tk.LEFT, padx=4)


        btn_frame = tk.Frame(left)
        btn_frame.pack(fill=tk.X, pady=4)
        tk.Button(btn_frame, text="Check Now", command=self.update_analysis, bg="#2b7").pack(side=tk.LEFT, padx=4)
        tk.Button(btn_frame, text="Generate Strong", command=self.generate_and_fill, bg="#79f").pack(side=tk.LEFT, padx=4)
        tk.Button(btn_frame, text="Export Last Result", command=self.export_last).pack(side=tk.LEFT, padx=4)
        tk.Button(btn_frame, text="Bulk Analyze File", command=self.bulk_analyze).pack(side=tk.LEFT, padx=4)

      
        progress_frame = tk.Frame(left)
        progress_frame.pack(fill=tk.X, pady=6)
        self.score_var = tk.IntVar(value=0)
        tk.Label(progress_frame, text="Score:").pack(side=tk.LEFT)
        self.score_label = tk.Label(progress_frame, text="0/100")
        self.score_label.pack(side=tk.LEFT, padx=6)
        self.progress = ttk.Progressbar(progress_frame, orient="horizontal", length=480, mode="determinate", maximum=100, variable=self.score_var)
        self.progress.pack(side=tk.LEFT, padx=4)

       
        result_box = tk.Frame(left)
        result_box.pack(fill=tk.BOTH, expand=True, pady=8)
        self.result_var = tk.StringVar(value="🔎 Results will appear here.")
        self.result_lbl = tk.Label(result_box, textvariable=self.result_var, justify="left", font=("Segoe UI", 11), anchor="nw")
        self.result_lbl.pack(fill=tk.X, padx=4, pady=4)

       
        sug_frame = tk.LabelFrame(left, text="Suggestions & Patterns", padx=6, pady=6)
        sug_frame.pack(fill=tk.BOTH, expand=True, pady=6)
        self.sug_text = tk.Text(sug_frame, height=8, wrap="word", font=("Segoe UI", 10))
        self.sug_text.pack(fill=tk.BOTH, expand=True)
        self.sug_text.config(state=tk.DISABLED)

        
        heat_frame = tk.LabelFrame(left, text="Segment Heatmap (per-character)", padx=6, pady=6)
        heat_frame.pack(fill=tk.X, pady=6)
        self.heat_text = tk.Text(heat_frame, height=2, font=("Consolas", 12), padx=4, pady=2)
        self.heat_text.pack(fill=tk.X)
        self.heat_text.config(state=tk.DISABLED)

        imp_frame = tk.LabelFrame(left, text="Improved Alternatives (click to copy)", padx=6, pady=6)
        imp_frame.pack(fill=tk.X, pady=6)
        self.imp_list = tk.Listbox(imp_frame, height=4, font=("Segoe UI", 10))
        self.imp_list.pack(fill=tk.X)
        self.imp_list.bind("<Double-Button-1>", lambda e: self.copy_from_list())


        graph_frame = tk.LabelFrame(left, text="Entropy Growth Graph", padx=6, pady=6)
        graph_frame.pack(fill=tk.BOTH, expand=True, pady=6)
        self.fig, self.ax = plt.subplots(figsize=(6,2))
        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        self.ax.set_title("Entropy Growth (as you type)")
        self.ax.set_xlabel("Characters")
        self.ax.set_ylabel("Entropy (bits)")

    
        pol_frame = tk.LabelFrame(right, text="Policy Checker", padx=6, pady=6)
        pol_frame.pack(fill=tk.X, pady=6)

     
        self.p_min_len = tk.IntVar(value=self.policy["min_length"])
        tk.Label(pol_frame, text="Min length:").grid(row=0,column=0, sticky="w")
        tk.Entry(pol_frame, textvariable=self.p_min_len, width=5).grid(row=0,column=1, sticky="w", padx=4)
        self.p_upper = tk.BooleanVar(value=self.policy["require_upper"])
        tk.Checkbutton(pol_frame, text="Require Uppercase", variable=self.p_upper).grid(row=1,column=0, columnspan=2, sticky="w")
        self.p_lower = tk.BooleanVar(value=self.policy["require_lower"])
        tk.Checkbutton(pol_frame, text="Require Lowercase", variable=self.p_lower).grid(row=2,column=0, columnspan=2, sticky="w")
        self.p_digits = tk.BooleanVar(value=self.policy["require_digits"])
        tk.Checkbutton(pol_frame, text="Require Digits", variable=self.p_digits).grid(row=3,column=0, columnspan=2, sticky="w")
        self.p_symbols = tk.BooleanVar(value=self.policy["require_symbols"])
        tk.Checkbutton(pol_frame, text="Require Symbols", variable=self.p_symbols).grid(row=4,column=0, columnspan=2, sticky="w")
        self.p_disallow_common = tk.BooleanVar(value=self.policy["disallow_common"])
        tk.Checkbutton(pol_frame, text="Disallow Common Passwords", variable=self.p_disallow_common).grid(row=5,column=0, columnspan=2, sticky="w")
        tk.Button(pol_frame, text="Apply Policy", command=self.apply_policy).grid(row=6,column=0, pady=6)

       
        hist_frame = tk.LabelFrame(right, text="Session History (masked)", padx=6, pady=6)
        hist_frame.pack(fill=tk.BOTH, expand=True, pady=6)
        self.hist_list = tk.Listbox(hist_frame, height=10)
        self.hist_list.pack(fill=tk.BOTH, expand=True)
        tk.Button(hist_frame, text="Export Session CSV", command=self.export_session).pack(pady=6)

  
        opt_frame = tk.LabelFrame(right, text="Options", padx=6, pady=6)
        opt_frame.pack(fill=tk.X, pady=6)
        self.dark_var = tk.BooleanVar(value=False)
        tk.Checkbutton(opt_frame, text="Dark Mode", variable=self.dark_var, command=self.toggle_theme).pack(anchor="w")
        self.auto_clip_var = tk.BooleanVar(value=False)
        tk.Checkbutton(opt_frame, text="Auto-clear clipboard after copy (10s)", variable=self.auto_clip_var).pack(anchor="w")

        
        tk.Button(right, text="Save Graph Snapshot", command=self.save_graph).pack(pady=6, fill=tk.X)

        
        self.update_analysis()

    
    def toggle_show(self):
        if self.entry.cget("show") == "":
            self.entry.config(show="*")
            self.toggle_btn.config(text="Show")
        else:
            self.entry.config(show="")
            self.toggle_btn.config(text="Hide")

    def generate_and_fill(self):
        pwd = generate_password(length=16, use_symbols=True)
        self.entry.delete(0, tk.END)
        self.entry.insert(0, pwd)
        self.update_analysis()

    def copy_results(self):
        text = self.result_var.get() + "\n" + self._get_suggestions_text()
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Copied", "Results copied to clipboard.")
        if self.auto_clip_var.get():
            # schedule clear
            self.root.after(10000, lambda: self.clear_clipboard_if_matches(text))

    def clear_clipboard_if_matches(self, text):
        try:
            cur = self.root.clipboard_get()
            if cur == text:
                self.root.clipboard_clear()
        except tk.TclError:
            pass

    def copy_from_list(self):
        sel = self.imp_list.curselection()
        if not sel: return
        pwd = self.imp_list.get(sel[0])
        self.root.clipboard_clear()
        self.root.clipboard_append(pwd)
        messagebox.showinfo("Copied", "Suggested password copied to clipboard.")
        if self.auto_clip_var.get():
            self.root.after(10000, lambda: self.clear_clipboard_if_matches(pwd))

    def apply_policy(self):
        self.policy["min_length"] = int(self.p_min_len.get())
        self.policy["require_upper"] = self.p_upper.get()
        self.policy["require_lower"] = self.p_lower.get()
        self.policy["require_digits"] = self.p_digits.get()
        self.policy["require_symbols"] = self.p_symbols.get()
        self.policy["disallow_common"] = self.p_disallow_common.get()
        messagebox.showinfo("Policy", "Policy applied.")
        self.update_analysis()

    
    def update_analysis(self):
        pwd = self.entry.get()
        entropy = calculate_entropy(pwd)
        strength_label, score = classify_strength(entropy)
        crack = estimate_crack_time(entropy)
        patterns = analyze_patterns(pwd)
        policy_issues = check_policy(pwd, self.policy)
        suggestions = []
        # suggestions from missing character classes
        if not re.search(LOWERCASE, pwd):
            suggestions.append("Add lowercase letters.")
        if not re.search(UPPERCASE, pwd):
            suggestions.append("Add uppercase letters.")
        if not re.search(DIGITS, pwd):
            suggestions.append("Include numbers.")
        if not re.search(SYMBOLS, pwd):
            suggestions.append("Add symbols for complexity.")
        if len(pwd) < self.policy.get("min_length",12):
            suggestions.append(f"Increase length to at least {self.policy.get('min_length')} characters.")
        
        suggestions += policy_issues

       
        result_lines = [
            f"🔒 Strength: {strength_label}    (Score: {score}/100)",
            f"🔢 Entropy: {entropy} bits",
            f"⏱ Estimated crack time (1e9 guesses/sec): {crack}",
            f"🔍 Policy checks: {'Pass' if not policy_issues else 'Fail'}"
        ]
        self.result_var.set("\n".join(result_lines))
        self.score_var.set(score)
        self.score_label.config(text=f"{score}/100")
       
        self.sug_text.config(state=tk.NORMAL)
        self.sug_text.delete("1.0", tk.END)
        if suggestions or patterns:
            for s in suggestions:
                self.sug_text.insert(tk.END, "• " + s + "\n")
            if patterns:
                self.sug_text.insert(tk.END, "\nPatterns detected:\n")
                for p in patterns:
                    self.sug_text.insert(tk.END, "• " + p + "\n")
        else:
            self.sug_text.insert(tk.END, "No suggestions — password looks strong.")
        self.sug_text.config(state=tk.DISABLED)

       
        self._update_heatmap(pwd)

        
        self._populate_improvements(pwd)

        
        entry_masked = mask_password(pwd)
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        record = {"time": timestamp, "masked": entry_masked, "strength": strength_label,
                  "entropy": entropy, "crack": crack}
        
        self.session_log.append(record)
        if len(self.session_log) > 200: self.session_log.pop(0)
        self._refresh_history()

       
        self._update_graph(pwd)

    def _update_heatmap(self, password):
        
        self.heat_text.config(state=tk.NORMAL)
        self.heat_text.delete("1.0", tk.END)
        for i, ch in enumerate(password):
            tag = f"c{i}"
            self.heat_text.insert(tk.END, ch, tag)
            # classify char
            if re.match(SYMBOLS, ch):
                color = "#2b7"  
            elif re.match(DIGITS, ch):
                color = "#7af"
            elif re.match(UPPERCASE, ch):
                color = "#9f9"
            elif re.match(LOWERCASE, ch):
                color = "#ffb86b"
            else:
                color = "#ddd"
            self.heat_text.tag_config(tag, foreground="black", background=color)
        self.heat_text.config(state=tk.DISABLED)

    def _populate_improvements(self, password):
        self.imp_list.delete(0, tk.END)
        suggestions = generate_improvements(password, count=6)
        for s in suggestions:
            self.imp_list.insert(tk.END, s)

    def _update_graph(self, password):
        self.ax.clear()
        if password:
            ent = [calculate_entropy(password[:i+1]) for i in range(len(password))]
            self.ax.plot(range(1,len(password)+1), ent, marker='o')
            self.ax.set_xlim(1, max(2,len(password)))
            self.ax.set_ylim(0, max(10, max(ent)+10))
        else:
            self.ax.plot([],[])
            self.ax.set_xlim(0,1)
            self.ax.set_ylim(0,1)
        self.ax.set_title("Entropy Growth")
        self.ax.set_xlabel("Characters")
        self.ax.set_ylabel("Entropy (bits)")
        self.ax.grid(True)
        self.canvas.draw()

    def _refresh_history(self):
        self.hist_list.delete(0, tk.END)
        for rec in self.session_log[-50:]:
            self.hist_list.insert(tk.END, f"{rec['time']} | {rec['masked']} | {rec['strength']} | {rec['entropy']} bits")

   
    def export_last(self):
        if not self.session_log:
            messagebox.showwarning("No Data", "No analysis to export.")
            return
        last = self.session_log[-1]
        fname = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text","*.txt")], title="Save Last Result")
        if not fname:
            return
        with open(fname, "w", encoding="utf-8") as f:
            f.write("Pro Password Analyzer - Single Result Export\n")
            f.write(f"Time: {last['time']}\n")
            f.write(f"Password (masked): {last['masked']}\n")
            f.write(f"Strength: {last['strength']}\n")
            f.write(f"Entropy: {last['entropy']} bits\n")
            f.write(f"Estimated Crack Time: {last['crack']}\n")
        messagebox.showinfo("Saved", f"Saved to {fname}")

    def export_session(self):
        if not self.session_log:
            messagebox.showwarning("No Data", "No session history available.")
            return
        fname = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")], title="Save Session CSV")
        if not fname:
            return
        with open(fname, "w", newline='', encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["time","masked","strength","entropy","crack"])
            for rec in self.session_log:
                writer.writerow([rec['time'], rec['masked'], rec['strength'], rec['entropy'], rec['crack']])
        messagebox.showinfo("Saved", f"Session exported to {fname}")

    def save_graph(self):
        fname = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG","*.png")], title="Save Graph PNG")
        if not fname:
            return
        self.fig.savefig(fname, dpi=200, bbox_inches='tight')
        messagebox.showinfo("Saved", f"Graph snapshot saved to {fname}")

    def bulk_analyze(self):
        fname = filedialog.askopenfilename(title="Open password list (one per line)", filetypes=[("Text","*.txt"),("All files","*.*")])
        if not fname:
            return
        out_rows = []
        with open(fname, "r", encoding="utf-8", errors="ignore") as f:
            lines = [ln.strip() for ln in f if ln.strip()]
        for ln in lines:
            entropy = calculate_entropy(ln)
            strength, score = classify_strength(entropy)
            crack = estimate_crack_time(entropy)
            patterns = analyze_patterns(ln)
            out_rows.append({"password": mask_password(ln), "strength": strength, "entropy": entropy, "crack": crack, "patterns": "; ".join(patterns)})
        # ask to save CSV
        outname = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")], title="Save bulk results")
        if not outname:
            return
        with open(outname, "w", newline='', encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["masked_password","strength","entropy","estimated_crack_time","patterns"])
            for r in out_rows:
                writer.writerow([r["password"], r["strength"], r["entropy"], r["crack"], r["patterns"]])
        messagebox.showinfo("Bulk Analysis", f"Analyzed {len(out_rows)} passwords. Results saved to {outname}")

   
    def toggle_theme(self):
        self.dark = self.dark_var.get()
        self.update_theme()

    def update_theme(self):
        bg = "#222" if self.dark else "#fafafa"
        fg = "#eee" if self.dark else "#111"
        
        widgets = self.root.winfo_children()
        self.root.configure(bg=bg)
        for w in widgets:
            try:
                w.configure(bg=bg, fg=fg)
            except Exception:
                pass
        self.result_lbl.configure(bg=bg, fg=fg)
        self.sug_text.configure(bg="#333" if self.dark else "#fff", fg="#eee" if self.dark else "#000")
        self.heat_text.configure(bg="#111" if self.dark else "#fff", fg="#eee" if self.dark else "#000")
        # redraw canvas background
        self.fig.patch.set_facecolor(bg)
        self.ax.set_facecolor(bg)
        self.canvas.draw()


def main():
    root = tk.Tk()
    app = ProPassApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
