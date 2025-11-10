# Transformer Attack Script
# Makes requests to random common APIs to test sequence-based anomaly detection

import requests
import random
import time
from collections import Counter

# Base URL
BASE_URL = "https://api.nexusmxp.com"

# 100 Common API endpoints
COMMON_APIS = [
    "/api/documents",
    "/api/users",
    "/api/auth/login",
    "/api/auth/logout",
    "/api/profile",
    "/api/settings",
    "/api/dashboard",
    "/api/notifications",
    "/api/messages",
    "/api/files",
    "/api/upload",
    "/api/download",
    "/api/search",
    "/api/filter",
    "/api/sort",
    "/api/paginate",
    "/api/create",
    "/api/update",
    "/api/delete",
    "/api/list",
    "/api/get",
    "/api/post",
    "/api/put",
    "/api/patch",
    "/api/admin",
    "/api/admin/users",
    "/api/admin/settings",
    "/api/admin/logs",
    "/api/admin/stats",
    "/api/admin/config",
    "/api/products",
    "/api/products/list",
    "/api/products/create",
    "/api/products/update",
    "/api/products/delete",
    "/api/orders",
    "/api/orders/create",
    "/api/orders/update",
    "/api/orders/cancel",
    "/api/cart",
    "/api/cart/add",
    "/api/cart/remove",
    "/api/cart/clear",
    "/api/checkout",
    "/api/payment",
    "/api/payment/process",
    "/api/payment/status",
    "/api/invoice",
    "/api/invoice/generate",
    "/api/invoice/download",
    "/api/reports",
    "/api/reports/generate",
    "/api/reports/export",
    "/api/analytics",
    "/api/analytics/dashboard",
    "/api/analytics/events",
    "/api/analytics/metrics",
    "/api/logs",
    "/api/logs/access",
    "/api/logs/error",
    "/api/logs/audit",
    "/api/health",
    "/api/status",
    "/api/version",
    "/api/info",
    "/api/config",
    "/api/config/get",
    "/api/config/set",
    "/api/session",
    "/api/session/create",
    "/api/session/validate",
    "/api/session/destroy",
    "/api/token",
    "/api/token/refresh",
    "/api/token/validate",
    "/api/permissions",
    "/api/permissions/check",
    "/api/permissions/grant",
    "/api/permissions/revoke",
    "/api/roles",
    "/api/roles/list",
    "/api/roles/assign",
    "/api/backup",
    "/api/backup/create",
    "/api/backup/restore",
    "/api/backup/list",
    "/api/export",
    "/api/export/csv",
    "/api/export/json",
    "/api/export/pdf",
    "/api/import",
    "/api/import/csv",
    "/api/import/json",
    "/api/validate",
    "/api/validate/email",
    "/api/validate/username",
    "/api/validate/token",
    "/api/reset",
    "/api/reset/password",
    "/api/reset/email",
    "/api/verify",
    "/api/verify/email",
    "/api/verify/phone",
    "/api/subscribe",
    "/api/unsubscribe",
    "/api/feedback",
    "/api/contact",
    "/api/support"
]

# Headers matching the original request
HEADERS = {
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


def make_request_to_api(api_path):
    """
    Makes a request to a specific API endpoint
    
    Args:
        api_path: API endpoint path (e.g., "/api/users")
        
    Returns:
        tuple: (success, status_code, api_path)
    """
    url = f"{BASE_URL}{api_path}"
    
    try:
        # Add some common query parameters randomly
        params = {}
        if random.random() > 0.5:
            params["page"] = str(random.randint(1, 10))
        if random.random() > 0.5:
            params["limit"] = str(random.randint(5, 50))
        if random.random() > 0.7:
            params["sort"] = random.choice(["asc", "desc"])
        
        response = requests.get(url, params=params, headers=HEADERS, timeout=10)
        return (True, response.status_code, api_path)
    except requests.exceptions.RequestException as e:
        return (False, None, api_path)


def run_transformer_attack(num_requests=100):
    """
    Makes requests to random common APIs
    
    Args:
        num_requests: Number of requests to make (default: 100)
    """
    print(f"Making {num_requests} requests to random common APIs...")
    print(f"Base URL: {BASE_URL}")
    print(f"Total available APIs: {len(COMMON_APIS)}")
    print("-" * 60)
    
    success_count = 0
    error_count = 0
    status_codes = Counter()
    accessed_apis = Counter()
    
    start_time = time.time()
    
    for i in range(num_requests):
        # Randomly select an API endpoint
        api_path = random.choice(COMMON_APIS)
        
        # Make the request
        success, status_code, path = make_request_to_api(api_path)
        
        if success:
            success_count += 1
            status_codes[status_code] += 1
            accessed_apis[path] += 1
        else:
            error_count += 1
        
        # Progress update every 10 requests
        if (i + 1) % 10 == 0:
            print(f"Progress: {i + 1}/{num_requests} requests completed")
        
        # Small delay to avoid overwhelming the server
        time.sleep(0.1)
    
    end_time = time.time()
    duration = end_time - start_time
    
    # Print results
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"Total Requests: {num_requests}")
    print(f"Successful: {success_count}")
    print(f"Failed: {error_count}")
    print(f"Duration: {duration:.2f} seconds")
    print(f"Requests per second: {num_requests / duration:.2f}")
    
    print(f"\nStatus Code Distribution:")
    for status_code, count in sorted(status_codes.items()):
        print(f"  {status_code}: {count}")
    
    print(f"\nTop 10 Most Accessed APIs:")
    for api, count in accessed_apis.most_common(10):
        print(f"  {api}: {count} requests")
    
    print(f"\nUnique APIs Accessed: {len(accessed_apis)}/{len(COMMON_APIS)}")


if __name__ == "__main__":
    print("Transformer Attack Script")
    print("Testing sequence-based anomaly detection with random API access patterns")
    print("=" * 60)
    run_transformer_attack(100)

