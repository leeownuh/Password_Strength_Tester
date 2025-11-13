from __future__ import annotations
import math
import re
import random
import string
import csv
import time
import os
import threading
import logging
from dataclasses import dataclass, field
from typing import List, Tuple, Dict, Optional
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
import hashlib

# optional dependency
try:
    import requests
except Exception:  # pragma: no cover - UI will warn if requests missing at runtime
    requests = None

# ------------------------- Logging ---------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger("propass")

# ------------------------- Constants --------------------------------
LOWERCASE = r"[a-z]"
UPPERCASE = r"[A-Z]"
DIGITS = r"[0-9]"
SYMBOLS = r"[^a-zA-Z0-9\s]"  # consider non-space non-alnum as symbol

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
    "disallow_common": True,
    # new option: whether to consult Have I Been Pwned
    "check_breach": False,
}

# Typical attacker guess rates (guesses/sec)
GUESSES_PER_SEC = {
    "online_throttled": 100.0,        # e.g., web login throttling
    "online_unthrottled": 10000.0,    # optimistic
    "offline_slow": 1e6,              # single GPU
    "offline_fast": 1e10,             # large cluster / botnet
}

# Have I Been Pwned settings
HIBP_USER_AGENT = "ProPassApp - HaveIBeenPwnedCheck"
HIBP_TIMEOUT = 6.0

# ------------------------- Data Classes -----------------------------
@dataclass
class AnalysisResult:
    entropy_bits: float
    strength_label: str
    score: int
    crack_time: str
    policy_issues: List[str] = field(default_factory=list)
    patterns: List[str] = field(default_factory=list)

# ------------------------- Analyzer Functions ----------------------

def calculate_entropy(password: str) -> float:
    """Estimate entropy in bits using charset pool heuristic.
    - Sum character class sizes based on presence
    - Fallback: use observed unique characters to refine estimate
    """
    if not password:
        return 0.0

    # Determine pool size by classes
    pool = 0
    if re.search(LOWERCASE, password):
        pool += 26
    if re.search(UPPERCASE, password):
        pool += 26
    if re.search(DIGITS, password):
        pool += 10
    if re.search(SYMBOLS, password):
        # try to use the distinct symbol set used for a slightly better estimate
        syms = set(ch for ch in password if re.match(SYMBOLS, ch))
        pool += max(10, len(syms))  # at least assume 10 possible symbols

    # if pool still zero (e.g., only whitespace) fall back to unique chars
    if pool == 0:
        pool = len(set(password)) or 1

    # guard: pool cannot exceed printable ascii
    pool = min(pool, 95)

    entropy = len(password) * math.log2(pool)
    return round(entropy, 2)


def classify_strength(entropy: float) -> Tuple[str, int]:
    """Return human label and a 0-100 score.
    The score is a smooth mapping from entropy into 0-100 and also capped based on thresholds.
    """
    if entropy <= 0:
        return "Very Weak", 0
    # smooth score: map 0-120 bits to 0-100
    score = int(max(0, min(100, entropy / 1.2)))

    if entropy < 28:
        return "Very Weak", score
    elif entropy < 36:
        return "Weak", score
    elif entropy < 60:
        return "Moderate", score
    elif entropy < 80:
        return "Strong", score
    else:
        return "Very Strong", score


def estimate_crack_time(entropy_bits: float, guesses_per_sec: float = GUESSES_PER_SEC["offline_slow"]) -> str:
    """Estimate time to brute-force half the space (on average). Return a friendly text.
    Uses 2^(entropy-1)/guesses_per_sec (average-case) but protects against overflow.
    """
    if entropy_bits <= 0:
        return "Instant"

    # average number of guesses is 2^(entropy-1)
    try:
        avg_guesses = 2 ** max(0, entropy_bits - 1)
    except OverflowError:
        return ">= many years"

    seconds = avg_guesses / max(1.0, guesses_per_sec)

    # human-friendly formatting
    units = [("ms", 1e-3), ("sec", 1), ("min", 60), ("hr", 3600), ("day", 86400), ("year", 86400 * 365), ("k years", 86400 * 365 * 1000)]
    if seconds < 1:
        return f"{seconds*1000:.2f} ms"
    for name, thresh in units[1:]:
        if seconds < thresh * 1000:  # some sensible cap
            if name == "sec":
                return f"{seconds:.2f} sec"
            elif name == "min":
                return f"{seconds/60:.2f} min"
            elif name == "hr":
                return f"{seconds/3600:.2f} hr"
            elif name == "day":
                return f"{seconds/86400:.2f} days"
            elif name == "year":
                return f"{seconds/(86400*365):.2f} years"
            else:
                return f">= {seconds/(86400*365*1000):.2f} k years"
    return f">= {seconds/(86400*365):.2e} years"


def analyze_patterns(password: str) -> List[str]:
    p = password or ""
    out = []
    if re.search(r"(.)\1{2,}", p):
        out.append("Repeated characters (e.g., aaa or 111)")
    low = p.lower()
    for seq in KEY_SEQS:
        if seq in low:
            out.append(f"Common sequence detected: '{seq}'")
            break
    if re.search(r"(19|20)\d{2}", p):
        out.append("Year-like sequence detected (e.g., 1990, 2023)")
    if p.lower() in COMMON_PASSWORDS:
        out.append("Exact common password found")
    # keyboard-dominance heuristic
    letters = sum(1 for ch in p.lower() if ch.isalpha())
    if len(p) >= 4 and letters >= len(p) * 0.75:
        out.append("Mostly letters — consider mixing character classes")
    return out


def check_policy(password: str, policy: dict) -> List[str]:
    issues = []
    if len(password) < policy.get("min_length", DEFAULT_POLICY["min_length"]):
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


def generate_password(length: int = 16, use_symbols: bool = True) -> str:
    chars = string.ascii_letters + string.digits
    if use_symbols:
        chars += "!@#$%^&*()-_=+[]{};:,.<>?/\\|"
    return ''.join(random.SystemRandom().choice(chars) for _ in range(max(4, length)))


def generate_improvements(seed: str, count: int = 5) -> List[str]:
    seed = (seed or "").strip()
    suggestions: List[str] = []
    if not seed:
        return [generate_password(length=16, use_symbols=True) for _ in range(count)]

    def leet(s: str) -> str:
        subs = {'a': '@', 's': '$', 'o': '0', 'i': '1', 'e': '3', 't': '7', 'l': '1'}
        return ''.join(subs.get(ch.lower(), ch) for ch in s)

    def insert_random(s: str, n: int = 3) -> str:
        alpha = string.ascii_letters + string.digits + "!@#"
        pos = random.randrange(0, len(s) + 1)
        rnd = ''.join(random.choice(alpha) for _ in range(n))
        return s[:pos] + rnd + s[pos:]

    tries = 0
    while len(suggestions) < count and tries < count * 8:
        tries += 1
        choice = random.choice(['leet', 'insert', 'lengthen', 'mix'])
        if choice == 'leet':
            cand = leet(seed)
        elif choice == 'insert':
            cand = insert_random(seed, n=random.randint(2, 5))
        elif choice == 'lengthen':
            cand = seed + '!' + generate_password(length=6, use_symbols=False)
        else:
            cand = leet(insert_random(seed, n=2)) + random.choice('!@#')
        if cand != seed and cand not in suggestions and len(cand) >= 12:
            suggestions.append(cand)
    while len(suggestions) < count:
        suggestions.append(generate_password(length=16, use_symbols=True))
    return suggestions


# ------------------------- Have I Been Pwned (k-Anonymity)  ----------
def check_pwned(password: str) -> int:
    """Check HIBP Pwned Passwords API using k-Anonymity.
    Returns:
      - 0 if not found
      - positive integer count if found (number of occurrences)
      - -1 if an error occurred or requests library is missing

    This function only sends the first 5 chars of the SHA-1 hash to the API — the
    full password or full hash are never transmitted.
    """
    if not password:
        return 0
    if requests is None:
        return -1
    try:
        sha1 = hashlib.sha1(password.encode('utf-8', errors='ignore')).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        headers = {'User-Agent': HIBP_USER_AGENT}
        resp = requests.get(url, headers=headers, timeout=HIBP_TIMEOUT)
        if resp.status_code != 200:
            logger.warning('HIBP returned status %s', resp.status_code)
            return -1
        # response lines: HASH_SUFFIX:COUNT
        for line in resp.text.splitlines():
            parts = line.split(":")
            if len(parts) != 2:
                continue
            if parts[0].upper() == suffix:
                try:
                    return int(parts[1].strip())
                except Exception:
                    return -1
        return 0
    except Exception as e:
        logger.exception('HIBP check failed')
        return -1

# ------------------------- GUI (Application) -----------------------
class ProPassApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Pro Password Auditor — Refactor + HIBP")
        self.root.geometry("980x740")
        self.policy = DEFAULT_POLICY.copy()
        self.session_log: List[Dict] = []
        self.logo_img = None
        self._build_ui()
        # try to auto-load a default logo if present
        default_logo = os.path.join('images', 'logo.png')
        if os.path.exists(default_logo):
            try:
                self.logo_img = tk.PhotoImage(file=default_logo)
                self.logo_label.configure(image=self.logo_img)
            except Exception:
                logger.info('Default logo found but failed to load.')
        self.update_analysis()

    def _build_ui(self):
        # Use themed ttk widgets
        self.style = ttk.Style()
        try:
            self.style.theme_use('clam')
        except Exception:
            pass

        main = ttk.Frame(self.root, padding=8)
        main.pack(fill=tk.BOTH, expand=True)

        # Left (analysis) / Right (settings)
        left = ttk.Frame(main)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        right = ttk.Frame(main, width=320)
        right.pack(side=tk.RIGHT, fill=tk.Y)

        # Title area (logo moved to right side as requested)
        title_frame = ttk.Frame(left)
        title_frame.pack(anchor='w', fill=tk.X)
        title = ttk.Label(title_frame, text="PROFESSIONAL PASSWORD ANALYZER", font=(None, 14, 'bold'))
        title.pack(side=tk.LEFT)

        entry_row = ttk.Frame(left)
        entry_row.pack(fill=tk.X, pady=6)
        ttk.Label(entry_row, text="Password:").pack(side=tk.LEFT)
        self.entry = ttk.Entry(entry_row, width=36, show='*')
        self.entry.pack(side=tk.LEFT, padx=6)
        self.entry.bind("<KeyRelease>", lambda e: self.update_analysis())

        # Eye button (toggles show/hide) and keep a small Load Logo for convenience (logo primarily shown on right)
        eye_btn = ttk.Button(entry_row, text='👁', width=3, command=self._toggle_eye)
        eye_btn.pack(side=tk.LEFT)
        ttk.Button(entry_row, text="Load Logo", command=self._load_logo).pack(side=tk.LEFT, padx=4)

        btn_row = ttk.Frame(left)
        btn_row.pack(fill=tk.X)
        btn_row.pack(fill=tk.X)
        ttk.Button(btn_row, text="Check Now", command=self.update_analysis).pack(side=tk.LEFT, padx=3)
        ttk.Button(btn_row, text="Generate Strong", command=self._generate_fill).pack(side=tk.LEFT, padx=3)
        ttk.Button(btn_row, text="Bulk Analyze File", command=self.bulk_analyze).pack(side=tk.LEFT, padx=3)

        # Result summary
        self.result_var = tk.StringVar(value="No analysis yet.")
        result_box = ttk.LabelFrame(left, text="Summary")
        result_box.pack(fill=tk.X, pady=6)
        ttk.Label(result_box, textvariable=self.result_var).pack(anchor='w', padx=6, pady=6)

        # Suggestions
        sug_frame = ttk.LabelFrame(left, text="Suggestions & Patterns")
        sug_frame.pack(fill=tk.BOTH, expand=True, pady=6)
        self.sug_text = tk.Text(sug_frame, height=8, wrap='word')
        self.sug_text.pack(fill=tk.BOTH, expand=True)
        self.sug_text.config(state=tk.DISABLED)

        # Graph
        graph_frame = ttk.LabelFrame(left, text="Entropy Growth")
        graph_frame.pack(fill=tk.BOTH, expand=True)
        self.fig, self.ax = plt.subplots(figsize=(6, 2))
        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Right: logo on top -> policy -> alternatives -> history
        logo_frame = ttk.Frame(right)
        logo_frame.pack(fill=tk.X, pady=(0,6))
        self.logo_label = ttk.Label(logo_frame)
        self.logo_label.pack(side=tk.RIGHT, anchor='ne')

        pol = ttk.LabelFrame(right, text="Policy")
        pol.pack(fill=tk.X, pady=6)
        ttk.Label(pol, text="Min length:").grid(row=0, column=0, sticky='w')
        self.p_min_len = tk.IntVar(value=self.policy['min_length'])
        ttk.Entry(pol, textvariable=self.p_min_len, width=5).grid(row=0, column=1, sticky='w', padx=4)
        self.p_upper = tk.BooleanVar(value=self.policy['require_upper'])
        ttk.Checkbutton(pol, text='Require Uppercase', variable=self.p_upper).grid(row=1, column=0, columnspan=2, sticky='w')
        self.p_lower = tk.BooleanVar(value=self.policy['require_lower'])
        ttk.Checkbutton(pol, text='Require Lowercase', variable=self.p_lower).grid(row=2, column=0, columnspan=2, sticky='w')
        self.p_digits = tk.BooleanVar(value=self.policy['require_digits'])
        ttk.Checkbutton(pol, text='Require Digits', variable=self.p_digits).grid(row=3, column=0, columnspan=2, sticky='w')
        self.p_symbols = tk.BooleanVar(value=self.policy['require_symbols'])
        ttk.Checkbutton(pol, text='Require Symbols', variable=self.p_symbols).grid(row=4, column=0, columnspan=2, sticky='w')
        self.p_disallow_common = tk.BooleanVar(value=self.policy['disallow_common'])
        ttk.Checkbutton(pol, text='Disallow Common', variable=self.p_disallow_common).grid(row=5, column=0, columnspan=2, sticky='w')
        # new: enable breach checking
        self.p_check_breach = tk.BooleanVar(value=self.policy.get('check_breach', False))
        ttk.Checkbutton(pol, text='Check breaches (Have I Been Pwned)', variable=self.p_check_breach).grid(row=6, column=0, columnspan=2, sticky='w')
        ttk.Button(pol, text='Apply', command=self._apply_policy).grid(row=7, column=0, pady=6)

        # Improved alternatives moved under policy (as requested)
        imp_frame_right = ttk.LabelFrame(right, text="Improved Alternatives (double-click to copy)")
        imp_frame_right.pack(fill=tk.X, pady=6)
        self.imp_list = tk.Listbox(imp_frame_right, height=6)
        self.imp_list.pack(fill=tk.X)
        self.imp_list.bind('<Double-Button-1>', self._copy_from_list)

        # history
        hist = ttk.LabelFrame(right, text='Session History (masked)')
        hist.pack(fill=tk.BOTH, expand=True, pady=6)
        self.hist_list = tk.Listbox(hist, height=12)
        self.hist_list.pack(fill=tk.BOTH, expand=True)
        ttk.Button(hist, text='Export CSV', command=self.export_session).pack(pady=6)

    # ---------------- UI helpers ---------------------------------
    def _toggle_eye(self):
        """Toggle password visibility using the eye button."""
        cur = self.entry.cget('show')
        if cur == '':
            self.entry.config(show='*')
        else:
            self.entry.config(show='')

    def _load_logo(self):
        """Prompt user to load a small PNG/GIF logo and display it next to the policy (right side)."""
        fname = filedialog.askopenfilename(title='Select logo', filetypes=[('PNG','*.png'),('GIF','*.gif'),('All','*.*')])
        if not fname:
            return
        try:
            img = tk.PhotoImage(file=fname)
            self.logo_img = img  # keep a reference
            self.logo_label.configure(image=img)
        except Exception as e:
            messagebox.showerror('Image error', f'Failed to load image: {e}')

    def _generate_fill(self):
        pwd = generate_password(length=18, use_symbols=True)
        self.entry.delete(0, tk.END)
        self.entry.insert(0, pwd)
        self.update_analysis()

    def _copy_from_list(self, event=None):
        sel = self.imp_list.curselection()
        if not sel:
            return
        pwd = self.imp_list.get(sel[0])
        # Be cautious: copying raw passwords to clipboard is a sensitive action
        if messagebox.askyesno('Copy password', 'Copy the suggested password to clipboard?'):
            self.root.clipboard_clear()
            self.root.clipboard_append(pwd)
            messagebox.showinfo('Copied', 'Password copied to clipboard (clear manually when done).')

    def _apply_policy(self):
        self.policy['min_length'] = int(self.p_min_len.get())
        self.policy['require_upper'] = self.p_upper.get()
        self.policy['require_lower'] = self.p_lower.get()
        self.policy['require_digits'] = self.p_digits.get()
        self.policy['require_symbols'] = self.p_symbols.get()
        self.policy['disallow_common'] = self.p_disallow_common.get()
        self.policy['check_breach'] = self.p_check_breach.get()
        messagebox.showinfo('Policy', 'Policy updated.')
        self.update_analysis()

    # ---------------- Analysis & UI update ------------------------
    def update_analysis(self):
        pwd = self.entry.get()
        entropy = calculate_entropy(pwd)
        strength, score = classify_strength(entropy)
        # choose reasonable attacker model for display
        crack = estimate_crack_time(entropy, guesses_per_sec=GUESSES_PER_SEC['offline_slow'])
        patterns = analyze_patterns(pwd)
        policy_issues = check_policy(pwd, self.policy)

        # optionally check breach status (do this in a background thread to keep UI responsive)
        breach_info: Optional[int] = None

        def do_breach_check():
            nonlocal breach_info
            if not self.policy.get('check_breach'):
                breach_info = None
            else:
                breach_info = check_pwned(pwd)
            # update UI on main thread
            self.root.after(0, lambda: self._finish_analysis_ui(entropy, strength, score, crack, patterns, policy_issues, breach_info))

        # start background breach check if enabled and password non-empty
        if self.policy.get('check_breach') and pwd:
            threading.Thread(target=do_breach_check, daemon=True).start()
            # put a provisional result while the check runs
            self.result_var.set(f"Strength: {strength}   (score: {score}/100)\nEntropy: {entropy} bits\nEstimated crack time (offline slow): {crack}\nBreach check: running...")
        else:
            # immediate UI update
            self._finish_analysis_ui(entropy, strength, score, crack, patterns, policy_issues, None)

        # improvements list (moved to right; update contents there)
        self.imp_list.delete(0, tk.END)
        for s in generate_improvements(pwd, count=6):
            self.imp_list.insert(tk.END, s)

        # session log entry will be recorded by _finish_analysis_ui when breach_info is known / not used

        # update graph (do this immediately)
        self._update_graph(pwd)

    def _finish_analysis_ui(self, entropy, strength, score, crack, patterns, policy_issues, breach_info):
        # build summary text
        summary = f"Strength: {strength}   (score: {score}/100)\nEntropy: {entropy} bits\nEstimated crack time (offline slow): {crack}"
        if breach_info is None:
            summary += "\nBreach check: disabled"
        elif breach_info == -1:
            summary += "\nBreach check: unavailable (network or dependency error)"
        elif breach_info == 0:
            summary += "\nBreach check: not found in known breaches"
        else:
            summary += f"\nBreach check: FOUND — occurred {breach_info} time(s) in public breaches"

        self.result_var.set(summary)

        # suggestions
        self.sug_text.config(state=tk.NORMAL)
        self.sug_text.delete('1.0', tk.END)
        if policy_issues:
            self.sug_text.insert(tk.END, 'Policy issues:\n')
            for it in policy_issues:
                self.sug_text.insert(tk.END, ' • ' + it + '\n')
        else:
            self.sug_text.insert(tk.END, 'No policy issues detected.\n')

        if patterns:
            self.sug_text.insert(tk.END, '\nPatterns:\n')
            for p in patterns:
                self.sug_text.insert(tk.END, ' • ' + p + '\n')

        # class suggestions
        pwd = self.entry.get()
        if not re.search(LOWERCASE, pwd): self.sug_text.insert(tk.END, '\n• Add lowercase letters.\n')
        if not re.search(UPPERCASE, pwd): self.sug_text.insert(tk.END, '• Add uppercase letters.\n')
        if not re.search(DIGITS, pwd): self.sug_text.insert(tk.END, '• Include numbers.\n')
        if not re.search(SYMBOLS, pwd): self.sug_text.insert(tk.END, '• Add symbols for complexity.\n')
        if len(pwd) < self.policy.get('min_length', 12):
            self.sug_text.insert(tk.END, f"• Increase length to at least {self.policy.get('min_length')} characters.\n")
        if breach_info and breach_info > 0:
            self.sug_text.insert(tk.END, "\n• This password appears in public data breaches — do NOT use it. Consider generating a new unique password.\n")
        elif breach_info == -1:
            self.sug_text.insert(tk.END, "\n• Breach check failed (network or missing 'requests' library).\n")

        self.sug_text.config(state=tk.DISABLED)

        # session log
        masked = mask_password(self.entry.get())
        ts = time.strftime('%Y-%m-%d %H:%M:%S')
        rec = {'time': ts, 'masked': masked, 'strength': strength, 'entropy': entropy}
        if breach_info is not None:
            rec['pwned_count'] = breach_info
        self.session_log.append(rec)
        if len(self.session_log) > 500:
            self.session_log.pop(0)
        self._refresh_history()

    def _update_graph(self, password: str):
        self.ax.clear()
        if password:
            ent = [calculate_entropy(password[:i + 1]) for i in range(len(password))]
            self.ax.plot(range(1, len(password) + 1), ent, marker='o')
            self.ax.set_xlim(1, max(2, len(password)))
            self.ax.set_ylim(0, max(10, max(ent) + 10))
        else:
            self.ax.plot([], [])
            self.ax.set_xlim(0, 1)
            self.ax.set_ylim(0, 1)
        self.ax.set_title('Entropy Growth')
        self.ax.set_xlabel('Characters')
        self.ax.set_ylabel('Entropy (bits)')
        self.ax.grid(True)
        self.canvas.draw()

    def _refresh_history(self):
        self.hist_list.delete(0, tk.END)
        for rec in self.session_log[-50:]:
            pwn = rec.get('pwned_count')
            pwn_str = f" | pwned:{pwn}" if pwn is not None else ""
            self.hist_list.insert(tk.END, f"{rec['time']} | {rec['masked']} | {rec['strength']} | {rec['entropy']} bits{pwn_str}")

    # ---------------- I/O tasks (threaded) -------------------------
    def export_session(self):
        if not self.session_log:
            messagebox.showwarning('No data', 'Session history is empty.')
            return
        fname = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV', '*.csv')])
        if not fname:
            return
        # do the write in a thread
        def _write():
            try:
                with open(fname, 'w', newline='', encoding='utf-8') as fh:
                    w = csv.writer(fh)
                    headers = ['time', 'masked', 'strength', 'entropy', 'pwned_count']
                    w.writerow(headers)
                    for r in self.session_log:
                        w.writerow([r.get('time'), r.get('masked'), r.get('strength'), r.get('entropy'), r.get('pwned_count', '')])
                self.root.after(0, lambda: messagebox.showinfo('Saved', f'Session exported to {fname}'))
            except Exception as e:
                logger.exception('Failed to export session')
                self.root.after(0, lambda: messagebox.showerror('Error', str(e)))
        threading.Thread(target=_write, daemon=True).start()

    def bulk_analyze(self):
        fname = filedialog.askopenfilename(title='Open password list', filetypes=[('Text', '*.txt'), ('All', '*.*')])
        if not fname:
            return
        outname = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV', '*.csv')], title='Save bulk results')
        if not outname:
            return

        def _process():
            try:
                with open(fname, 'r', encoding='utf-8', errors='ignore') as fh:
                    lines = [ln.strip() for ln in fh if ln.strip()]
                rows = []
                for ln in lines:
                    ent = calculate_entropy(ln)
                    strength, score = classify_strength(ent)
                    crack = estimate_crack_time(ent)
                    pats = analyze_patterns(ln)
                    pwn = ''
                    if self.policy.get('check_breach') and requests is not None:
                        c = check_pwned(ln)
                        pwn = str(c) if c != -1 else 'error'
                    rows.append([mask_password(ln), strength, ent, crack, '; '.join(pats), pwn])
                with open(outname, 'w', newline='', encoding='utf-8') as outfh:
                    w = csv.writer(outfh)
                    w.writerow(['masked_password', 'strength', 'entropy', 'estimated_crack_time', 'patterns', 'pwned_count'])
                    w.writerows(rows)
                self.root.after(0, lambda: messagebox.showinfo('Bulk Analysis', f'Analyzed {len(rows)} passwords. Results saved to {outname}'))
            except Exception as e:
                logger.exception('Bulk analyze failed')
                self.root.after(0, lambda: messagebox.showerror('Error', str(e)))

        threading.Thread(target=_process, daemon=True).start()

# ---------------- Utilities ---------------------------------------

def mask_password(pwd: str) -> str:
    if not pwd:
        return ''
    if len(pwd) <= 4:
        return '*' * len(pwd)
    return pwd[0] + '*' * (len(pwd) - 2) + pwd[-1]

# ---------------- Main --------------------------------------------

def main():
    root = tk.Tk()
    app = ProPassApp(root)
    root.mainloop()

if __name__ == '__main__':
    main()
