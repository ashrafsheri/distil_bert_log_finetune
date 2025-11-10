# Malicious HTTP Request - SQL Injection Attack
# This request will trigger the rule-based detection model

import requests

# Option 1: Simple OR 1=1 pattern (matches pattern 86)
malicious_request_1 = """GET /api/documents?page=1+OR+1=1&limit=6 HTTP/1.1
Host: api.nexusmxp.com
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: en-US,en;q=0.9
Accept: application/json, text/plain, */*
Sec-Ch-Ua: "Chromium";v="141", "Not?A_Brand";v="8"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36
Sec-Ch-Ua-Mobile: ?0
Origin: https://nexusmxp.com
Sec-Fetch-Site: same-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://nexusmxp.com/
Accept-Encoding: gzip, deflate, br
Priority: u=1, i
Connection: keep-alive

"""

# Option 2: UNION SELECT pattern (matches pattern 86)
# Python script to execute the malicious request
def make_malicious_request_2():
    """
    Makes a malicious HTTP request with SQL injection payload
    This will trigger the rule-based detection model
    """
    url = "https://api.nexusmxp.com/api/documents"
    
    # SQL injection payload in query parameters
    params = {
        "page": "1 UNION SELECT * FROM users",
        "limit": "6"
    }
    
    # Headers matching the original request
    headers = {
        "Host": "api.nexusmxp.com",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": "application/json, text/plain, */*",
        "Sec-Ch-Ua": '"Chromium";v="141", "Not?A_Brand";v="8"',
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
        "Sec-Ch-Ua-Mobile": "?0",
        "Origin": "https://nexusmxp.com",
        "Sec-Fetch-Site": "same-site",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": "https://nexusmxp.com/",
        "Accept-Encoding": "gzip, deflate, br",
        "Priority": "u=1, i",
        "Connection": "keep-alive"
    }
    
    try:
        # Make the GET request with SQL injection payload
        response = requests.get(url, params=params, headers=headers, timeout=10)
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        print(f"Response Body: {response.text[:500]}")  # First 500 chars
        
        return response
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return None

# Execute the malicious request
if __name__ == "__main__":
    print("Making malicious request with SQL injection payload...")
    print("Payload: page=1 UNION SELECT * FROM users")
    print("-" * 60)
    make_malicious_request_2()
