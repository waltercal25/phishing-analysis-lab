# phishing-analysis-lab
Basic phishing email investigation using VirusTotal and header analysis

📧 Phishing Email Analysis Lab
🧠 Objective
Analyze a suspicious email using open-source tools and document IOCs (Indicators of Compromise).

🔧 Tools Used
VirusTotal
Header Analyzers
Any.Run (sandbox optional)
Notepad / Screenshot tools

📝 Steps Taken
Collected suspicious email headers
Parsed headers with MXToolbox to identify sender IP
Observed forged domains and mismatched SPF records
Submitted URL in body to VirusTotal
VirusTotal flagged it with 8+ detections (malware/phishing)
Documented findings

| Type             | Value                              |
| ---------------- | ---------------------------------- |
| Malicious Domain | `secure-login123[.]xyz`            |
| IP Address       | `198.51.100.23`                    |
| File Hash        | `d41d8cd98f00b204e9800998ecf8427e` |

📌 Summary
This lab showed how to analyze phishing emails using free tools. I identified a fake domain, extracted IOCs, and documented them clearly.
