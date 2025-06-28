# 🛡️ Lightweight Antivirus Scanner in C++ with YARA + AI-based False Positive Detection

This is a **lightweight C++ antivirus engine** prototype that combines traditional signature scanning, heuristic analysis using **YARA rules**, and an **AI-based validation layer** using OpenRouter LLMs to minimize false positives.

---

## 📦 Features

### 🔐 Signature-Based File Scanning
- Reads files in binary mode
- Computes **SHA-256 hash**
- Compares against a known malware hash database

### 🧠 Heuristic Scan (YARA Integration)
- Uses **LibYARA** to scan files for known malicious patterns
- Matches against custom rulesets (e.g., suspicious imports, shellcode, script behaviors)
- Supports rule compilation, efficient matching, and result categorization

### 🤖 AI-based False Positive Validation
- Integrates with **OpenRouter.ai** using `deepseek-r1` model
- Evaluates:
  - File path
  - Entropy
  - Heuristic reason
- Returns a verdict: **TRUE POSITIVE** or **FALSE POSITIVE**
- Reduces false positives by ~30% in testing

---


## 🛠 Technologies Used

- C++17
- LibYARA (`libyara-dev`)
- Python 3.x (for AI validation & web UI)
- OpenRouter (https://openrouter.ai) with DeepSeek LLM

---


## 🚀 Getting Started with quick scan

### 1. Clone the Repository
```bash
git clone https://github.com/sandeep-prabhakula/my-antivirus.git
cd my-antivirus
```

### 2. Build the C++ Quick Scanner
```bash
  cd Malicious\ file\ Scanner/
  g++ hello.cpp -o hello -lssl -lcrypto
```
### 3. Run Quick Scanner
```bash
  ./hello
```
## Getting started with Heuristic Scan

### 1. Build the C++ Heuristic Scanner
```bash
cd Heuristic\ Scanner/
g++ -o heuristicScanner heuristicScanner.cpp -lyara
```

### 2. Run Heuristic Scan
```bash
./heuristicScanner 
```

### 4. AI False Positive Filtering (Optional)
```bash
cd AIHeuristicScan/
pip install -r requirements.txt
python main.py
```

Set your `OPENROUTER_API_KEY` in a `.env` file.

---

## ⚙️ Environment Setup

Create `.env` in `AIHeuristicScan/`:

```env
OPENROUTER_API_KEY=your_openrouter_api_key
```

---

## 🧪 Example Output

```
[+] Scanned: /tmp/setup.sh
[+] Heuristic Match: Uses suspicious shell behavior
[!] YARA Match: Shell_Dropper.yar

[AI Validator]
Path: /tmp/setup.sh
Entropy: 7.3
Heuristic Reason: Obfuscated bash commands
→ Verdict: TRUE POSITIVE (high entropy and untrusted location)
```

---

## 🧱 Roadmap

- [x] Signature-based file scanning
- [x] YARA heuristic rule scanning
- [x] YARA rule compiler and optimizer
- [x] AI-based post-validation (OpenRouter)
- [ ] Background scan daemon
- [ ] Real-time system monitoring
- [ ] Threat dashboard with analytics

---

## 📜 License

MIT License.  
Free to use, modify, and contribute under fair security practices.

---

## 🙌 Contributing

PRs are welcome. Please open an issue before submitting large features.

---

## 📣 Shoutout

Built with ❤️ to explore how traditional AV tools can be augmented with LLMs.  
Let’s secure systems smarter, not harder.

---

## 🔗 GitHub Repo

Feel free to ⭐ the repo and share ideas:
[[https://github.com/<your-username>/lightweight-antivirus]([https://github.com/<your-username>/lightweight-antivirus](https://https://github.com/sandeep-prabhakula/my-antivirus/t)
)
]
