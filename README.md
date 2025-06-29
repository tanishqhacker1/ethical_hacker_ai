# Ethical Hacker AI Assistant

A powerful, voice- and text-controlled AI assistant for Kali Linux, Windows, and Termux. Automate ethical hacking, bug bounty, forensics, coding, OSINT, and daily tasks with natural language commands.

---

## ✨ Features

- **Voice & Text Command Support:** Switch between typing and speaking commands.
- **Voice Assistant:** Speaks responses using TTS.
- **Automated Recon & Bug Bounty:** Run `nmap`, `theHarvester`, `whois`, `dnsenum`, and more with a single command.
- **Shodan Integration:** Search Shodan from your terminal.
- **Tool Automation:** Supports dozens of Kali Linux and forensics tools.
- **Data Recovery & Forensics:** Automate recovery and forensic analysis.
- **Learning & Coding:** Ask questions, generate code, and get tutorials.
- **App/Game/Website Scaffolding:** Instantly create project skeletons.
- **Local LLM Integration:** Run prompts with Ollama, text-generation-webui, koboldcpp, etc.
- **Daily Use:** Get the date, make notes, search the web, and more.

---

## 🚀 Quick Start

### 1. Clone the Repository

```sh
git clone https://github.com/yourusername/ethical-hacker-ai.git
cd ethical-hacker-ai
```

### 2. Install Requirements

```sh
pip install -r requirements.txt
```
Or manually:
```sh
pip install pyttsx3 SpeechRecognition shodan requests
```

### 3. Add Your Shodan API Key

Edit `ethical_hacker_ai.py` and replace:
```python
SHODAN_API_KEY = 'shodan api key here'
```
with your actual Shodan API key.

### 4. Run the Assistant

```sh
python ethical_hacker_ai.py
```

---

## 🗣️ Usage

- **Text Command:**  
  Type commands at the prompt.
- **Voice Command:**  
  Type `voicemode on` to enable, then speak your command.
- **Switch Back:**  
  Type `voicemode off` to return to text mode.

**Example Commands:**
```
nmap scanme.nmap.org
shodan apache
bugbounty example.com
recoverdata /dev/sdb1
forensics exiftool image.jpg
ask What is SQL injection?
codegen python port scanner
makeapp MyApp "A todo app"
duckduckgo how to use nmap
```

---

## 🛠️ Supported Tools

- Recon: `nmap`, `theHarvester`, `whois`, `dnsenum`, `recon-ng`, etc.
- Exploitation: `hydra`, `sqlmap`, `msfconsole`, `searchsploit`, etc.
- Forensics: `autopsy`, `sleuthkit`, `volatility`, `binwalk`, `exiftool`, etc.
- Data Recovery: `foremost`, `testdisk`, `photorec`
- Local LLMs: `ollama`, `webui`, `koboldcpp`
- And many more (see code for full list).

---

## 📝 Notes

- **For ethical and legal use only.**  
  Always have permission before scanning or testing any system.
- **Voice features** require a working microphone and TTS support.
- **Some tools** require Kali Linux or similar environments.

---

## 📄 License

MIT License

---

## 🤝 Contributing

Pull requests and suggestions are welcome!

---

## 📷 Screenshot

![screenshot](screenshot.png)

---

## ⭐ Credits

make by tanishq mohite

Made with ❤️ for the ethical hacking and open-source community.
