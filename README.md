
---

# 🔐 Pro Password Auditor (Advanced GUI Tool)

**Language:** Python 3.8+
**License:** MIT
**Status:** ✅ Stable
**Author:** [leeownuh](https://github.com/leeownuh)
**Made with ❤️ for Security Enthusiasts**

---

## 🧩 OVERVIEW

The **Pro Password Auditor** is a **professional-grade graphical tool** that helps users analyze and strengthen passwords through **entropy-based scoring**, **pattern detection**, and **policy compliance checks**.
It visualizes password strength in real time using **graphs, heatmaps, and interactive feedback**, empowering users to understand how secure their passwords truly are.

---

## ⚙️ FEATURES

* 📊 **Entropy Calculation:** Uses Shannon Entropy to quantify password randomness.
* 🚦 **Dynamic Strength Classification:** Instant rating — Very Weak → Very Strong.
* 🔍 **Pattern Recognition:** Detects keyboard sequences, years, common passwords, and repeated characters.
* 🧠 **Smart Improvement Suggestions:** Suggests stronger password alternatives with leet transformations, added symbols, or random inserts.
* 🔒 **Policy Checker:** Adjustable corporate-grade policy (min length, required character types, etc.).
* 📈 **Entropy Growth Graph:** Live visualization of entropy as you type.
* 🎨 **Heatmap Visualization:** Color-coded per-character complexity insight.
* 🧾 **Bulk Password Analyzer:** Analyze hundreds of passwords from a file and export CSV results.
* 💾 **Session Logging & Export:** Keep a history of all tests and export them in text or CSV format.
* 🌙 **Dark/Light Mode:** Seamless theme switching for comfort.
* 🧰 **Clipboard Safety:** Optional auto-clear feature after copy for privacy.

---

## 🖥️ USAGE

### ▶️ Run the program:

```bash
python pro_password_tool.py
```

### 💡 Main Functions:

* Type or paste a password → Instant analysis.
* View **strength**, **entropy**, and **estimated crack time**.
* Explore **patterns**, **policy results**, and **entropy graph**.
* Click **Generate Strong** to auto-create a secure password.
* **Double-click** on suggested passwords to copy them instantly.
* Use **Export Session CSV** or **Save Graph Snapshot** to record results.

---

## 🧮 ENTROPY REFERENCE

| Entropy (bits) | Classification | Example Crack Time (@1e9 guesses/sec) |
| -------------- | -------------- | ------------------------------------- |
| < 28           | 🔴 Very Weak   | Instant                               |
| 28–35          | 🟠 Weak        | Seconds–Minutes                       |
| 36–59          | 🟡 Moderate    | Hours–Days                            |
| 60–79          | 🟢 Strong      | Years                                 |
| ≥ 80           | 🟣 Very Strong | Thousands of Years                    |

---

## 📦 INSTALLATION

### Requirements:

* Python 3.8 or higher
* Required libraries:

  ```bash
  pip install matplotlib
  ```

*(Tkinter comes preinstalled with most Python distributions.)*

---

## 📁 PROJECT STRUCTURE

```
ProPasswordAuditor/
 ┣ pro_password_tool.py
 ┣ README.md
 ┗ LICENSE
```

---

## 🧑‍💻 AUTHOR

**Created by:** [Ownuh (Leona Kokerai)](https://github.com/leeownuh)
**Field:** Cybersecurity & Software Development
**Quote:** *“Passwords are the first defense — make them unbreakable.”*

---

## 🪪 LICENSE

This project is distributed under the **MIT License**.
You’re free to use, modify, and distribute this tool with proper attribution.

