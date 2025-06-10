Suggestion: *Use PowerShell Version 7 For Better Result*


🚀 Usage
Follow these steps to run the SOC Email Header Analyzer PowerShell script:

1. 🔑 Set Your VirusTotal API Key
Before running the script, make sure to replace the placeholder API key in the script with your own.

Open the script file in a text editor (e.g., EmailHeaderAnalyzer.ps1)

Find this line at the top:

powershell
Copy
Edit
$VT_APIKey = "YOUR_API_KEY_HERE"
Replace the value with your VirusTotal API key

2. 📥 Run the Script
Open PowerShell and navigate to the folder where the script is saved. Then execute:

powershell
Copy
Edit
.\EmailHeaderAnalyzer.ps1
3. 📋 Paste the Email Header
When prompted, paste the full raw email headers.

Once you're done pasting, press Enter on an empty line to signal the end of input.

4. 🔍 View the Analysis
The script will:

Parse and display key header fields (From, To, Subject, etc.)

Show SPF/DKIM/DMARC results

Extract all Received headers and IPs

Query VirusTotal for reputation details of each IP (country, owner, threat stats, passive DNS, etc.)

🛠 Example Output
powershell
Copy
Edit
💼 SOC Email Header Analyzer
📩 Paste full email headers (press Enter on an empty line to finish):

📬 [+] Basic Header Fields
   ✉ From         : Alice <alice@example.com>
   ✉ To           : Bob <bob@example.org>
...

🔎 [+] VirusTotal IP Scan Results

🚨 Checking IP: 192.0.2.1
🧠 IP Overview: 192.0.2.1
   🌍 Country        : US
   🏢 Owner          : Example ISP
...
💡 Notes
VirusTotal API lookups are rate-limited; ensure your API key has enough quota.

You can further customize or extend the script for your environment.

