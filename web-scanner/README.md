# 🛡️ Web Application Security Scanner

A Python-based tool that scans websites for **common vulnerabilities** like missing security headers, SQL Injection, and Cross-Site Scripting (XSS).  
This project is intended for **educational purposes** to practice **web application security testing**.

---

## ⚡ Features
- ✅ Check for missing security headers  
- ✅ Test basic SQL Injection payloads  
- ✅ Test basic XSS payloads  
- ✅ Generates a report in `reports/scan_report.txt`

---

## 📂 Project Structure
web-scanner/
│── web_scanner.py # Main script
│── requirements.txt # Dependencies
│── README.md # Documentation
│── reports/
│ └── scan_report.txt # Output report

yaml
Copy code

---

## 🚀 Usage
1. Clone the repository:
```bash
git clone https://github.com/YOUR_USERNAME/web-scanner.git
cd web-scanner
Create & activate virtual environment (optional but recommended):

bash
Copy code
python -m venv .venv
.\.venv\Scripts\activate   # Windows
source .venv/bin/activate  # Linux/Mac
Install dependencies:

bash
Copy code
pip install -r requirements.txt
Run the scanner:

bash
Copy code
python web_scanner.py
Results will be saved in:

bash
Copy code
reports/scan_report.txt
📊 Example Output
pgsql
Copy code
[-] X-Frame-Options: Missing
[-] Strict-Transport-Security: Missing
[-] Content-Security-Policy: Missing
[-] X-Content-Type-Options: Missing
[+] No SQL Injection vulnerability found.
[+] No XSS vulnerability found.
⚠️ Disclaimer
This project is strictly for educational and research purposes.
Do not use it on websites without proper authorization. Unauthorized testing is illegal.

yaml
Copy code

---

Buddy, if you want, I can also make a **2-line resume-friendly description** for this Project 5 so you can directly paste it into your CV like we did for the others.  

Do you want me to do that next?