

---

# 🔐 Ownuh SecurePass Analyzer 

**Language:** Python 3.8+  
**License:** MIT  
**Status:** ✅ Stable  
**Author:** [leeownuh (Leona Kokerai)](https://github.com/leeownuh)  
**Made with ❤️ for Security Enthusiasts**

---

## 🏷️ PROJECT BADGES

![GitHub release (latest by date)](https://img.shields.io/github/v/release/leeownuh/ownuh-securepass?color=brightgreen&logo=github)
![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/leeownuh/ownuh-securepass/build.yml?logo=githubactions&label=Build)
![GitHub Repo stars](https://img.shields.io/github/stars/leeownuh/ownuh-securepass?style=social)
![GitHub all releases](https://img.shields.io/github/downloads/leeownuh/ownuh-securepass/total?logo=github)
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Last Commit](https://img.shields.io/github/last-commit/leeownuh/ownuh-securepass?logo=git&label=Last%20Commit)

---

## 🧩 OVERVIEW

**Ownuh SecurePass Analyzer** is a **professional-grade graphical password auditing tool** designed to help users **analyze, visualize, and strengthen passwords**.  
It combines **entropy-based scoring**, **pattern detection**, and **policy-driven evaluation** with rich **visual feedback**, empowering individuals and organizations to understand their password strength in real time.

---

## ⚙️ FEATURES

* 📊 **Entropy Calculation:** Uses Shannon Entropy to measure randomness and predict strength.  
* 🚦 **Dynamic Strength Classification:** Instantly classifies from Very Weak → Very Strong.  
* 🔍 **Pattern Recognition:** Detects keyboard patterns, dictionary words, years, sequences, and repeated characters.  
* 🧠 **Smart Suggestions:** Generates stronger password alternatives using leet-style mutations, symbol insertions, and capitalization mixes.  
* 🔒 **Policy Compliance Engine:** Customizable corporate-grade policy (length, character types, special symbols).  
* 📈 **Entropy Growth Graph:** Live graph that shows entropy increase as you type.  
* 🎨 **Heatmap Visualization:** Visual complexity map highlighting weak segments of a password.  
* 🧾 **Bulk Analyzer:** Import hundreds of passwords via CSV and export detailed reports.  
* 💾 **Session Logging:** Save your analysis history as `.csv` or `.txt`.  
* 🌙 **Dark/Light Theme:** Switch seamlessly between light and dark interfaces.  
* 🧰 **Clipboard Safety:** Optional timed clipboard clearing for enhanced privacy.

---
## ▶️ Download

Get the latest release here: [GitHub Releases](https://github.com/leeownuh/ownuh-securepass/releases)


## 🖥️ USAGE

### ▶️ Run the program:
```bash
python ownuh_securepass_analyzer.py
````

### 💡 Main Functions:

* Type or paste a password to instantly view:

  * Strength
  * Entropy score
  * Estimated crack time
* Explore detailed **pattern and policy reports**.
* Generate random secure passwords via **Generate Strong**.
* **Double-click** on suggestions to copy them instantly.
* Export analysis or graph snapshots for later review.

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
  pip install matplotlib requests pillow
  ```

*(Tkinter comes preinstalled with most Python distributions.)*

---

## 🧰 BUILD (Optional for Developers)

You can build standalone executables using **PyInstaller** or **GitHub Actions**.

### Manual build:

```bash
pyinstaller --noconfirm --clean --onefile --windowed \
  --add-data "images/logo.png:images" \
  --icon=assets/app.ico \
  ownuh_securepass_analyzer.py
```

### GitHub Actions build:

Automated builds are configured in `.github/workflows/build.yml`.
Tag your release with:

```bash
git tag v1.0.0
git push origin v1.0.0
```

The workflow will build Windows, macOS, and Linux binaries and upload them to the **Releases** page.

---

## 📁 PROJECT STRUCTURE

```
ownuh-securepass/
 ┣ ownuh_securepass_analyzer.py
 ┣ requirements.txt
 ┣ README.md
 ┣ LICENSE
 ┗ .github/
    ┗ workflows/
       ┗ build.yml
```
---

## 🛡️ SECURITY & PRIVACY NOTICE

**Ownuh SecurePass Analyzer** is designed with privacy in mind:

* **No passwords are stored or transmitted** outside your local machine unless you explicitly export them.  
* **Optional breach checking** uses the **Have I Been Pwned** k-anonymity API — only partial SHA-1 hash prefixes are sent, never your full password.  
* Session logs are **local only**, and sensitive passwords are **masked by default** in history views and CSV exports.  
* Clipboard operations are manual and can be **cleared automatically** after use for safety.  

By design, this tool ensures your sensitive data **remains private and under your control** at all times.

---

## 🧑‍💻 AUTHOR

**Created by:** [Ownuh (Leona Kokerai)](https://github.com/leeownuh)
**Field:** Cybersecurity & Software Development
**Quote:** *“Passwords are the first defense — make them unbreakable.”*

---

## 🪪 LICENSE

This project is licensed under the **MIT License**.
You are free to use, modify, and distribute this tool with proper attribution.

© 2025 **Ownuh Security Tools Project** — All rights reserved.

---

```

---

