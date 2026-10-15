# My Bio

Nicholas Michael Kloster is an independent security researcher focused on AI/LLM infrastructure security and reverse engineering.

He is the author of five CVEs across CISA-coordinated ICS disclosure and Cisco enterprise platforms, with additional accepted findings at Amazon, Google, Anthropic, Fortinet, TencentOS, DocketWise, and others.

He builds and maintains Ablation, an open-source reverse engineering framework.

He has built over 130 open-source tools for AI and ML infrastructure security, including aimap (218 service fingerprints across the AI stack), the Visor tool family (14 tools for AI infrastructure assessment and red teaming), and four purpose-built vector database scanners. His public research corpus, AI-LLM-Infrastructure-OSINT, covers 376 case studies and 88 methodology insights across 33 platform categories.

He served from 2015 to 2023 on active duty in the Infantry, separating as a Staff Sergeant with two deployments to Afghanistan. 

He holds Instructor and Mountaineering qualifications from the Northern Warfare Training Center in Alaska earning him a SQI "E", completed SOF-adjacent schools, and is a certified Master Resilience Trainer earning him the Skill Identifier (ASI) "8R".

During that time he completed reverse engineering courses through the Department of Defense Cyber Crime Center and volunteered with ITDRC. He trained with the President's Hundred while stationed in Fairbanks and was certified in their long-range marksmanship course.

<details>
<summary>The Department of Defense Cyber Crime Center Certifications</summary>

- A Brief History of Cryptography (B-CR-CE-14)
- Advanced NTFS Analysis
- Advanced Persistent Threats
- Advanced Regular Expressions (A-SC-PA-14)
- Aircrack Suite (I-SC-WR-14)
- Analyzing Binary Logs
- Analyzing Commercial Spyware on Android Devices
- Analyzing Malware With Cuckoo (I-LX-MD-20)
- Analyzing Memory (I-LX-MD-20a)
- Anatomy and Static Analysis of a Windows Portable Executable (I-W-MD-13)
- Anatomy of a Buffer Overflow (I-LX-TE-15)
- Android Acquisition (I-LX-MF-12)
- Application Layer Protocol Analysis (I-CR-NP-17)
- Authorizing Official - On-Demand (AO-OD)
- Autopsy Basics (I-CR-FT-16)
- AWS Infrastructure (I-AZ-CI-20)
- Basic Configuration of Cisco Routers and Switches (B-CR-CI-14)
- Basic YARA (B-CR-MD-20)
- Behavior Analysis of Malicious Portable Executables (I-CR-MD-14)
- Cerberus Analysis in FTK (I-LX-MD-15)
- Collecting BitLocker-encrypted Data
- Collecting System Information and Searching Data with PowerShell
- Command-line SSL Tricks
- Cyber Fundamentals 100 (CF100-OD)
- Cyber Risk Management
- Data Carving in Wireshark
- Detecting Anti-Forensic Techniques
- Detecting Zero-day Attacks with Sysinternals (I-CR-MD-14a)
- DISA STIG Overview (I-CR-RC-20a)
- Domain Fronting
- Exploiting Stack Buffer Overflow (I-CR-TE-21a)
- File Carving in EnCase (B-LX-FD-17)
- File Sharing With FreeNAS
- File Transfer for Threat Emulators
- Google for Investigators (B-G-TE-15)
- GUI Tools for Linux Computer Incident Response
- HTTP in Burp Suite (I-CR-TE-17)
- ICS/SCADA Basics
- Indicators of Compromise (I-CR-TE-24)
- Internet of Things in Forensics
- Intro to i2 Analyst's Notebook
- Introduction to ArcSight ESM (B-CR-CI-16)
- Introduction to Arduino (B-CR-PA-16a)
- Introduction to Axiom (B-CR-FT-23)
- Introduction to Digital Cryptography (B-CR-CE-14a)
- Introduction to EnCase Case Analyzer (B-CR-FT-15)
- Introduction to NetWitness Investigator (B-CR-NP-14)
- Introduction to Socat
- Introduction to Windows 11
- iOS Security
- IT Disaster Recovery Planning
- Linux Essentials - On-Demand (LXE-OD)
- Malicious Botnets (I-CR-TE-16)
- Managing Digital Footprints
- Managing Network Traffic Using Snort
- Microsoft Windows Computer Management (I-W-CI-22)
- Netcat & Tcpdump
- NetFlow Overview
- Network Defense With Honeypots (I-CR-TE-18b)
- Network Enumeration - Attacker Tactics
- Network Intrusions Basics - On-Demand
- Network Monitoring - Traffic Analysis
- Network Security Monitoring Using Security Onion (I-CR-NP-15c)
- Network Security Monitoring Using Snort
- Nmap Tool Suite
- Open Source Tools for Incident Response (B-CR-FT-20)
- Packet Analysis With Wireshark (I-CR-NP-16a)
- Protocol Analysis Basics (B-CR-NP-17a)
- Ransomware Lifecycles, Mitigations, and Future (I-CR-RC-23)
- Real-time Large Data Acquisitions in Linux
- Scanning With Zenmap
- Security Content Automation Protocol
- StormSystem 101
- Sysinternals Tools (B-CR-FT-18)
- System Administration With Ansible
- Traffic Collection Basics (B-CR-NP-17d)
- Using EnCase
- Using FTK Imager
- Vulnerability Management
- Vulnerability Scanning with Tenable Nessus
- Windows Forensic Artifacts: Evidence of Program Execution
- Windows Log Analysis with Splunk (B-W-CI-21)
- Windows Management Instrumentation Command-line
- Windows PowerShell Essentials (B-W-PA-21)
- Zeek Integration into ELK (B-CR-NP-21a)

</details>


# Sponsors

Thanks for checking out the tool.

A few months ago I was working through a security assessment and kept hitting the same wall. Claude kept defaulting to password spraying every single time. That drove me insane. Too slow, too noisy.

So I asked CC "what's main thing in our way?"
CC said Cisco ASA.
I'd never touched Cisco anything, I had to google what ASA meant.
Running out of resources and not wanting to give up on the elusive problem to be solved. I thought to myself, why don't we just reverse engineer it and like seep through the cracks.

Which led me to thinly peeling back each layer. Reading tons of reverse engineering books, research papers, books on regression theory, looking into Microsoft Excel's reverse engineering algorithm. Pretty cool. Which then led me to practically putting on the hat of a Cisco Engineer (metaphorically) and studying Cisco books and how everything works. I don't even remember the whole thing it was like a week long madman's Charlie from Always Sunny in Philadelphia meme thing going on as my girlfriend just smiled and supported because she's a genius and is super pretty.

But anyway. Fast forward to a structured story telling architecture:

Claude wanted to use Ghidra. I didn't want to learn a rubix cube of nonsense. I wanted to understand reverse engineering, I was in a rush and Ghidra looked overwhelming. Not that it isn't a reliable tool. (Hello NSA)
But reverse engineering is already really complex, and a complex GUI just adds one more layer of murky understanding. And O'Reilly Media only has like 4 books on reverse engineering and two of them are Ghidra and IDA PRO. Luckily I signed up for an account with them when I was still in the Army and they provided me with a free membership. So respect to them.

Anyway.

My hubris led to two cool things: reverse engineering Cisco ASA LINA source, and contributing the first layer of Ablation.

I have completely fallen in love with reverse engineering.

It gives me the same euphoric jaw clenching problem solving task completion that hacking did and it keeps me out of trouble.

## Goal

The target machine is a System76 Pangolin Pro at $3,873. Every sponsorship goes directly toward hardware that makes the work faster and the tool better.

---

## Pay

**GitHub Sponsors:** [github.com/sponsors/Ablation-Tool](https://github.com/sponsors/Ablation-Tool)

**Cash App:** $nicholaskloster2

**Bitcoin (BTC):** bc1qu3s92ff3s2d72cugyrne6n73khlsumf2sxhpex
