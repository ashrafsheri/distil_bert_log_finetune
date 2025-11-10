# Normal HTTP Request
# Makes a single normal HTTP request (no attack payload)

import requests

def make_normal_request():
    """
    Makes a normal HTTP request without any attack payload
    """
    url = "https://api.nexusmxp.com/api/documents"
    
    # Normal query parameters
    params = {
        "page": "1",
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
        # Make the GET request
        response = requests.get(url, params=params, headers=headers, timeout=10)
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        print(f"Response Body: {response.text[:500]}")  # First 500 chars
        
        return response
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return None


# Execute the normal request
if __name__ == "__main__":
    print("Making normal HTTP request...")
    print("URL: https://api.nexusmxp.com/api/documents")
    print("Params: page=1&limit=6")
    print("-" * 60)
    make_normal_request()

