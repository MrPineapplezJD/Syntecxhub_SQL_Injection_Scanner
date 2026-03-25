# 🔐 SQL Injection Scanner (Python)

A lightweight SQL Injection Scanner built in Python that detects vulnerabilities in web applications by testing URL parameters and HTML forms.

---

## 🚀 Features

* 🔍 Scans URL parameters for SQL injection vulnerabilities
* 🧪 Detects vulnerabilities using:

  * Error-based detection
  * Content-length comparison
* 🧾 Scans HTML forms (GET & POST methods)
* ⚡ Multi-threaded scanning using `ThreadPoolExecutor`
* 📁 Saves results to a structured JSON file
* 🔐 Supports authenticated scanning using sessions

---

## 🛠️ Technologies Used

* Python 3
* requests
* BeautifulSoup (bs4)
* concurrent.futures

---

## 📦 Installation

Clone the repository:

```bash
git clone https://github.com/MrPineapplezJD/Syntecxhub_SQL_Injection_Scanner.git
cd Syntecxhub_SQL_Injection_Scanner
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## ▶️ Usage

Run the scanner:

```bash
python SQL_Injection_Scanner.py
```

Enter a target URL when prompted:

```text
http://localhost/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit
```

---

## 🧪 Testing Environment

This project was tested using:

* DVWA (Damn Vulnerable Web Application) running on XAMPP (Apache & MySQL)

DVWA is a deliberately vulnerable web application used for practicing web security testing.

---

## ⚠️ Disclaimer

This tool is for **educational purposes only**.
Do not use it on websites without permission.

---

## 📁 Output Example

Results are saved in `results.json`:

```json
{
    "url": "http://localhost/DVWA/...",
    "payload": "' OR '1'='1",
    "type": "url",
    "status": "possible_vulnerability"
}
```
---

## 🧠 Learning Outcomes

- Understanding SQL Injection vulnerabilities
- Working with HTTP requests and sessions
- Parsing HTML using BeautifulSoup
- Automating security testing processes
- Writing multi-threaded Python applications

---

## 👤 Author

**Emmanuel J Deoduth**
Aspiring Cybersecurity / Software Developer

