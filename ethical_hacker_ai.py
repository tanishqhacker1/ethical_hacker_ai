import subprocess
import shodan
import requests
import pyttsx3
import speech_recognition as sr
import datetime

# Replace with your actual Shodan API key
SHODAN_API_KEY = 'shodan api key here'

# Initialize Shodan API
api = shodan.Shodan(SHODAN_API_KEY)

voice_mode = False

def speak(text):
    """Speak the given text using TTS."""
    engine = pyttsx3.init()
    engine.say(text)
    engine.runAndWait()

def listen():
    """Listen for a voice command and return as text."""
    recognizer = sr.Recognizer()
    with sr.Microphone() as source:
        print("Listening for command...")
        audio = recognizer.listen(source)
    try:
        command = recognizer.recognize_google(audio)
        print(f"You said: {command}")
        return command
    except Exception as e:
        print(f"Voice recognition error: {e}")
        return ""

def set_voicemode(state):
    global voice_mode
    if state == 'on':
        voice_mode = True
        return "Voice mode enabled."
    else:
        voice_mode = False
        return "Voice mode disabled."

def run_nmap(target):
    """Run Nmap scan on the target."""
    try:
        result = subprocess.check_output(['nmap', '-A', target], stderr=subprocess.STDOUT)
        return result.decode()
    except subprocess.CalledProcessError as e:
        return f"Error running Nmap: {e.output.decode()}"

def shodan_search(query):
    """Search Shodan for the given query."""
    try:
        results = api.search(query)
        output = f"Results found: {results['total']}\n"
        for result in results['matches'][:5]:
            output += f"IP: {result['ip_str']}\nData: {result['data']}\n---\n"
        return output
    except shodan.APIError as e:
        return f"Shodan API error: {e}"

def run_tool(tool, args):
    """Run a specified Kali Linux tool with arguments."""
    try:
        result = subprocess.check_output([tool] + args, stderr=subprocess.STDOUT)
        return result.decode()
    except FileNotFoundError:
        return f"Tool '{tool}' not found. Is it installed?"
    except subprocess.CalledProcessError as e:
        return f"Error running {tool}: {e.output.decode()}"

def power_wordlist(output_file, length, charset):
    """Generate a powerful wordlist using crunch."""
    try:
        result = subprocess.check_output([
            'crunch', str(length), str(length), charset, '-o', output_file
        ], stderr=subprocess.STDOUT)
        return f"Wordlist generated: {output_file}"
    except FileNotFoundError:
        return "Crunch tool not found. Please install it."
    except subprocess.CalledProcessError as e:
        return f"Error running crunch: {e.output.decode()}"

def make_tool(toolname, code):
    """Create a new Python tool with the given name and code."""
    if not toolname.endswith('.py'):
        toolname += '.py'
    try:
        with open(toolname, 'w') as f:
            f.write(code)
        return f"Tool '{toolname}' created."
    except Exception as e:
        return f"Error creating tool: {e}"

def ask_ai(question):
    """Answer hacking/ethical hacking questions using an AI API (placeholder)."""
    # Placeholder: Replace with a real API call if available
    return f"[AI Answer Placeholder] You asked: {question}\n(Integrate with an AI API for real answers.)"

def codegen(language, description):
    """Generate code in any language for a described task (placeholder)."""
    # Placeholder: Replace with a real code generation API if available
    return f"[CodeGen Placeholder] Generate {language} code for: {description}\n(Integrate with a code generation API for real code.)"

def makelang(language_name):
    """Generate a basic skeleton for a new programming language (fun placeholder)."""
    skeleton = f"// {language_name} - A new programming language skeleton\n" \
               f"// (This is a placeholder. Real language design is complex!)\n" \
               f"syntax = '...';\nsemantics = '...';\ninterpreter = function(code) {{ /* ... */ }};"
    filename = f"{language_name}_skeleton.txt"
    with open(filename, 'w') as f:
        f.write(skeleton)
    return f"Skeleton for new language '{language_name}' created as {filename}."

def bugreport(target, vulnerability, details):
    """Generate a simple bug bounty report file."""
    import datetime
    report = f"Bug Bounty Report\n" \
             f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n" \
             f"Target: {target}\n" \
             f"Vulnerability: {vulnerability}\n" \
             f"Details:\n{details}\n" \
             f"---\n" \
             f"Steps to Reproduce:\n1. ...\n2. ...\n" \
             f"Impact: ...\n" \
             f"Recommendation: ...\n"
    filename = f"bugreport_{target}_{vulnerability}.txt".replace(' ', '_')
    with open(filename, 'w') as f:
        f.write(report)
    return f"Bug bounty report created: {filename}"

def repair_os():
    """Suggest and optionally run common Linux OS repair commands."""
    suggestions = [
        "sudo apt update && sudo apt upgrade",
        "sudo apt --fix-broken install",
        "sudo dpkg --configure -a",
        "sudo fsck -Af -V",
        "sudo systemctl restart NetworkManager",
        "sudo systemctl restart gdm3 (or lightdm, sddm, etc.)",
        "sudo reboot"
    ]
    return ("Common OS repair commands:\n" +
            "\n".join(suggestions) +
            "\nRun these commands as needed for your issue.")

def repair_device(device_name):
    """Suggest troubleshooting steps for a device."""
    device_fixes = {
        'wifi': [
            "Check if WiFi is enabled (rfkill list)",
            "Restart NetworkManager: sudo systemctl restart NetworkManager",
            "Check drivers: sudo lshw -C network",
            "Reconnect to the network"
        ],
        'audio': [
            "Check volume and mute settings",
            "Restart audio: pulseaudio -k && pulseaudio --start",
            "Check alsamixer",
            "Check audio output device settings"
        ],
        'bluetooth': [
            "Restart Bluetooth: sudo systemctl restart bluetooth",
            "Check device pairing",
            "Check rfkill for blockages"
        ],
        'display': [
            "Restart display manager: sudo systemctl restart gdm3 (or lightdm, sddm, etc.)",
            "Check cable connections",
            "Check xrandr for display settings"
        ]
    }
    fixes = device_fixes.get(device_name.lower(), ["No specific suggestions. Try rebooting or checking device logs."])
    return f"Troubleshooting steps for {device_name}:\n" + "\n".join(fixes)

def teach(topic):
    """Provide a step-by-step guide or explanation for any topic (placeholder)."""
    return f"[Teach Placeholder] Step-by-step guide for: {topic}\n(Integrate with an AI API for real tutorials.)"

def do_task(task):
    """Attempt to perform a task or guide the user (placeholder)."""
    return f"[Do Placeholder] Attempting to do: {task}\n(Integrate with an AI API or automation for real actions.)"

def writebook(title, topic):
    """Generate a placeholder book file."""
    filename = f"book_{title.replace(' ', '_')}.txt"
    content = f"[Book Placeholder]\nTitle: {title}\nTopic: {topic}\n\n(Integrate with an AI API for real book content.)\n"
    with open(filename, 'w') as f:
        f.write(content)
    return f"Book created: {filename}"

def writesong(title, style):
    """Generate a placeholder song file."""
    filename = f"song_{title.replace(' ', '_')}.txt"
    content = f"[Song Placeholder]\nTitle: {title}\nStyle/Topic: {style}\n\n(Integrate with an AI API for real song lyrics and music.)\n"
    with open(filename, 'w') as f:
        f.write(content)
    return f"Song created: {filename}"

def writenote(title, content):
    """Generate a note file."""
    filename = f"note_{title.replace(' ', '_')}.txt"
    with open(filename, 'w') as f:
        f.write(content)
    return f"Note created: {filename}"

def live_search(query):
    """Perform a live web search (placeholder for real search engine API)."""
    # Placeholder: Replace with a real search engine API call
    return f"[Search Placeholder] Results for: {query}\n(Integrate with a search engine API for real results.)"

def bugbounty_workflow(target):
    """Automate bug bounty recon workflow and save results."""
    results = []
    # Nmap scan
    try:
        nmap_result = run_nmap(target)
        with open(f"bugbounty_{target}_nmap.txt", 'w') as f:
            f.write(nmap_result)
        results.append("Nmap scan saved.")
    except Exception as e:
        results.append(f"Nmap error: {e}")
    # theHarvester
    try:
        harvester_result = subprocess.check_output(['theharvester', '-d', target, '-b', 'all'], stderr=subprocess.STDOUT)
        with open(f"bugbounty_{target}_theharvester.txt", 'w') as f:
            f.write(harvester_result.decode())
        results.append("theHarvester results saved.")
    except Exception as e:
        results.append(f"theHarvester error: {e}")
    # Whois
    try:
        whois_result = subprocess.check_output(['whois', target], stderr=subprocess.STDOUT)
        with open(f"bugbounty_{target}_whois.txt", 'w') as f:
            f.write(whois_result.decode())
        results.append("Whois results saved.")
    except Exception as e:
        results.append(f"Whois error: {e}")
    # DNSenum
    try:
        dnsenum_result = subprocess.check_output(['dnsenum', target], stderr=subprocess.STDOUT)
        with open(f"bugbounty_{target}_dnsenum.txt", 'w') as f:
            f.write(dnsenum_result.decode())
        results.append("DNSenum results saved.")
    except Exception as e:
        results.append(f"DNSenum error: {e}")
    return "\n".join(results)

def makeapp(name, description):
    filename = f"app_{name.replace(' ', '_')}.txt"
    content = f"[App Placeholder]\nName: {name}\nDescription: {description}\n(Integrate with a real app generator for code.)\n"
    with open(filename, 'w') as f:
        f.write(content)
    return f"App placeholder created: {filename}"

def makegame(name, description):
    filename = f"game_{name.replace(' ', '_')}.txt"
    content = f"[Game Placeholder]\nName: {name}\nDescription: {description}\n(Integrate with a real game generator for code.)\n"
    with open(filename, 'w') as f:
        f.write(content)
    return f"Game placeholder created: {filename}"

def makewebsite(name, description):
    filename = f"website_{name.replace(' ', '_')}.txt"
    content = f"[Website Placeholder]\nName: {name}\nDescription: {description}\n(Integrate with a real website generator for code.)\n"
    with open(filename, 'w') as f:
        f.write(content)
    return f"Website placeholder created: {filename}"

def ollama_run(model, prompt):
    """Run a prompt with a local LLM using Ollama."""
    try:
        result = subprocess.check_output(['ollama', 'run', model, prompt], stderr=subprocess.STDOUT)
        return result.decode()
    except Exception as e:
        return f"Ollama error: {e}"

def ollama_start(model):
    """Start a model with Ollama."""
    try:
        result = subprocess.check_output(['ollama', 'start', model], stderr=subprocess.STDOUT)
        return result.decode()
    except Exception as e:
        return f"Ollama start error: {e}"

def ollama_stop(model):
    """Stop a model with Ollama."""
    try:
        result = subprocess.check_output(['ollama', 'stop', model], stderr=subprocess.STDOUT)
        return result.decode()
    except Exception as e:
        return f"Ollama stop error: {e}"

def webui_instructions():
    return ("To launch text-generation-webui, run:\n"
            "cd text-generation-webui && python server.py\n"
            "Then open http://localhost:7860 in your browser.")

def koboldcpp_instructions():
    return ("To launch koboldcpp, run:\n"
            "cd koboldcpp && ./koboldcpp --model <your_model.gguf>\n"
            "Then open http://localhost:5001 in your browser.")

def recover_data(target):
    """Automate data recovery using foremost, testdisk, and photorec."""
    results = []
    # Foremost
    try:
        foremost_out = f"recovery_foremost_{target}.out"
        result = subprocess.check_output(['foremost', '-i', target, '-o', foremost_out], stderr=subprocess.STDOUT)
        results.append(f"Foremost recovery output in {foremost_out}")
    except Exception as e:
        results.append(f"Foremost error: {e}")
    # TestDisk (interactive, so just suggest)
    results.append("TestDisk is interactive. Run: sudo testdisk")
    # PhotoRec (interactive, so just suggest)
    results.append("PhotoRec is interactive. Run: sudo photorec")
    return "\n".join(results)

def forensics_tool(tool, args):
    """Run a forensics tool with arguments and save output."""
    try:
        output_file = f"forensics_{tool}_{'_'.join(args)}.txt"
        result = subprocess.check_output([tool] + args, stderr=subprocess.STDOUT)
        with open(output_file, 'w') as f:
            f.write(result.decode())
        return f"{tool} output saved to {output_file}"
    except Exception as e:
        return f"{tool} error: {e}"

# Update parse_and_run_command to handle new commands

def parse_and_run_command(cmd):
    """Parse user command and run the appropriate tool or function."""
    if cmd.startswith('nmap '):
        target = cmd.split(' ', 1)[1]
        return run_nmap(target)
    elif cmd.startswith('shodan '):
        query = cmd.split(' ', 1)[1]
        return shodan_search(query)
    elif cmd.startswith('powerwordlist '):
        parts = cmd.split()
        if len(parts) == 4:
            output_file = parts[1]
            length = int(parts[2])
            charset = parts[3]
            return power_wordlist(output_file, length, charset)
        else:
            return "Usage: powerwordlist <output_file> <length> <charset>"
    elif cmd.startswith('maketool '):
        parts = cmd.split(' ', 2)
        if len(parts) == 3:
            toolname = parts[1]
            code = parts[2]
            return make_tool(toolname, code)
        else:
            return "Usage: maketool <toolname> <code>"
    elif cmd.startswith('ask '):
        question = cmd[4:]
        return ask_ai(question)
    elif cmd.startswith('codegen '):
        parts = cmd.split(' ', 2)
        if len(parts) == 3:
            language = parts[1]
            description = parts[2]
            return codegen(language, description)
        else:
            return "Usage: codegen <language> <description>"
    elif cmd.startswith('makelang '):
        parts = cmd.split(' ', 1)
        if len(parts) == 2:
            language_name = parts[1]
            return makelang(language_name)
        else:
            return "Usage: makelang <language_name>"
    elif cmd.startswith('bugreport '):
        parts = cmd.split(' ', 3)
        if len(parts) == 4:
            target = parts[1]
            vulnerability = parts[2]
            details = parts[3]
            return bugreport(target, vulnerability, details)
        else:
            return "Usage: bugreport <target> <vulnerability> <details>"
    elif cmd == 'repair os':
        return repair_os()
    elif cmd.startswith('repair device '):
        parts = cmd.split(' ', 2)
        if len(parts) == 3:
            device_name = parts[2]
            return repair_device(device_name)
        else:
            return "Usage: repair device <device_name>"
    elif cmd.startswith('teach '):
        topic = cmd[6:]
        return teach(topic)
    elif cmd.startswith('do '):
        task = cmd[3:]
        return do_task(task)
    elif cmd.startswith('writebook '):
        parts = cmd.split(' ', 2)
        if len(parts) == 3:
            title = parts[1]
            topic = parts[2]
            return writebook(title, topic)
        else:
            return "Usage: writebook <title> <topic>"
    elif cmd.startswith('writesong '):
        parts = cmd.split(' ', 2)
        if len(parts) == 3:
            title = parts[1]
            style = parts[2]
            return writesong(title, style)
        else:
            return "Usage: writesong <title> <style or topic>"
    elif cmd.startswith('writenote '):
        parts = cmd.split(' ', 2)
        if len(parts) == 3:
            title = parts[1]
            content = parts[2]
            return writenote(title, content)
        else:
            return "Usage: writenote <title> <content>"
    elif cmd.startswith('search '):
        query = cmd[7:]
        return live_search(query)
    elif cmd.startswith('bugbounty '):
        parts = cmd.split(' ', 1)
        if len(parts) == 2:
            target = parts[1]
            return bugbounty_workflow(target)
        else:
            return "Usage: bugbounty <target>"
    elif cmd.startswith('makeapp '):
        parts = cmd.split(' ', 2)
        if len(parts) == 3:
            name = parts[1]
            description = parts[2]
            return makeapp(name, description)
        else:
            return "Usage: makeapp <name> <description>"
    elif cmd.startswith('makegame '):
        parts = cmd.split(' ', 2)
        if len(parts) == 3:
            name = parts[1]
            description = parts[2]
            return makegame(name, description)
        else:
            return "Usage: makegame <name> <description>"
    elif cmd.startswith('makewebsite '):
        parts = cmd.split(' ', 2)
        if len(parts) == 3:
            name = parts[1]
            description = parts[2]
            return makewebsite(name, description)
        else:
            return "Usage: makewebsite <name> <description>"
    elif cmd.startswith('ollama '):
        parts = cmd.split(' ', 2)
        if len(parts) == 3:
            model = parts[1]
            prompt = parts[2]
            return ollama_run(model, prompt)
        else:
            return "Usage: ollama <model> <prompt>"
    elif cmd.startswith('ollama_start '):
        parts = cmd.split(' ', 1)
        if len(parts) == 2:
            model = parts[1]
            return ollama_start(model)
        else:
            return "Usage: ollama_start <model>"
    elif cmd.startswith('ollama_stop '):
        parts = cmd.split(' ', 1)
        if len(parts) == 2:
            model = parts[1]
            return ollama_stop(model)
        else:
            return "Usage: ollama_stop <model>"
    elif cmd == 'webui':
        return webui_instructions()
    elif cmd == 'koboldcpp':
        return koboldcpp_instructions()
    elif cmd.startswith('recoverdata '):
        parts = cmd.split(' ', 1)
        if len(parts) == 2:
            target = parts[1]
            return recover_data(target)
        else:
            return "Usage: recoverdata <device|file>"
    elif cmd.startswith('forensics '):
        parts = cmd.split(' ', 2)
        if len(parts) == 3:
            tool = parts[1]
            args = parts[2].split()
            return forensics_tool(tool, args)
        else:
            return "Usage: forensics <tool> <args>"
    elif cmd.lower() in ["what is todays date", "what's todays date", "what is today's date", "what's today's date"]:
        return datetime.datetime.now().strftime("Today's date is %Y-%m-%d.")
    else:
        # List of supported Kali tools
        supported_tools = [
            'nikto', 'hydra', 'gobuster', 'wpscan', 'sqlmap', 'john', 'hashcat',
            'dirb', 'dirbuster', 'msfconsole', 'searchsploit', 'whatweb', 'theharvester',
            'nmap', 'enum4linux', 'smbclient', 'ftp', 'netcat', 'nc', 'curl', 'wget',
            'whois', 'dnsenum', 'dnsrecon', 'recon-ng', 'sslscan', 'sslyze', 'nikto',
            'masscan', 'amass', 'fierce', 'snmpwalk', 'snmpcheck', 'xhydra', 'medusa',
            'burpsuite', 'zaproxy', 'aircrack-ng', 'ettercap', 'wireshark', 'tcpdump',
            'ncat', 'socat', 'proxychains', 'maltego', 'setoolkit', 'beef-xss', 'msfvenom',
            'crunch', 'cewl', 'hashid', 'hash-identifier', 'yara', 'radare2', 'gdb',
            'apktool', 'jadx', 'dex2jar', 'mobSF', 'apktool', 'binwalk', 'foremost',
            'strings', 'exiftool', 'volatility', 'autopsy', 'sleuthkit', 'pdfid', 'pdf-parser',
            # Advanced and post-exploitation tools
            'empire', 'crackmapexec', 'bloodhound', 'neo4j', 'responder', 'impacket-smbserver',
            'impacket-smbclient', 'impacket-secretsdump', 'impacket-psexec', 'impacket-wmiexec',
            'impacket-atexec', 'impacket-dcomexec', 'impacket-getTGT', 'impacket-getUserSPNs',
            'impacket-mimikatz', 'kerbrute', 'rubeus', 'certipy', 'ldapdomaindump', 'mitm6',
            'mitmproxy', 'bettercap', 'crackmapexec', 'smbmap', 'enum4linux-ng', 'kerberoast',
            'gpp-decrypt', 'linpeas', 'winpeas', 'pspy', 'chisel', 'socat', 'nishang', 'powershell',
            'evil-winrm', 'smbclient', 'rpcclient', 'smbmap', 'ldapsearch', 'adidnsdump', 'bloodhound-python',
            'sharpHound', 'neo4j-console', 'neo4j-admin', 'neo4j-import', 'neo4j-shell', 'neo4j-bolt',
            'neo4j-cypher-shell', 'neo4j-backup', 'neo4j-browser', 'neo4j-etl', 'neo4j-migrate',
            'neo4j-restore', 'neo4j-status', 'neo4j-stop', 'neo4j-start', 'neo4j-restart',
            'neo4j-cluster', 'neo4j-enterprise', 'neo4j-community', 'neo4j-desktop',
            'neo4j-server', 'neo4j-shell-tools', 'neo4j-spatial', 'neo4j-streams',
            'neo4j-udc', 'neo4j-unstable', 'neo4j-upgrade', 'neo4j-wrapper',
            'neo4j-zip', 'neo4j-admin-import', 'neo4j-admin-dump', 'neo4j-admin-load',
            'neo4j-admin-report', 'neo4j-admin-restore', 'neo4j-admin-set-initial-password',
            'neo4j-admin-unbind', 'neo4j-admin-upgrade', 'neo4j-admin-version',
            'neo4j-admin-help', 'neo4j-admin-list', 'neo4j-admin-migrate',
            'neo4j-admin-move', 'neo4j-admin-remove', 'neo4j-admin-rename',
            'neo4j-admin-repair', 'neo4j-admin-reset', 'neo4j-admin-resume',
            'neo4j-admin-revoke', 'neo4j-admin-rollback', 'neo4j-admin-rotate',
            'neo4j-admin-run', 'neo4j-admin-set', 'neo4j-admin-show', 'neo4j-admin-shutdown',
            'neo4j-admin-start', 'neo4j-admin-status', 'neo4j-admin-stop', 'neo4j-admin-store',
            'neo4j-admin-sync', 'neo4j-admin-unlock', 'neo4j-admin-upgrade', 'neo4j-admin-validate',
            'neo4j-admin-version', 'neo4j-admin-wait', 'neo4j-admin-zap',
        ]
        parts = cmd.split()
        if parts and parts[0] in supported_tools:
            tool = parts[0]
            args = parts[1:]
            return run_tool(tool, args)
        else:
            # Fallback: treat as a general question for AI
            return ask_ai(cmd)

def main():
    print("Ethical Hacker AI Assistant")
    print("Type or speak a tool command (e.g., 'nmap <target>', 'shodan <query>', or 'exit')")
    global voice_mode
    while True:
        if voice_mode:
            cmd = listen()
        else:
            cmd = input('> ').strip()
        if cmd == 'exit':
            break
        if cmd.startswith('voicemode '):
            state = cmd.split(' ', 1)[1]
            response = set_voicemode(state)
            print(response)
            if voice_mode:
                speak(response)
            continue
        output = parse_and_run_command(cmd)
        print(output)
        if voice_mode:
            speak(output)

if __name__ == '__main__':
    main()
