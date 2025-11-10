# Isolation Forest Attack Script
# Makes HTTP requests 1000 times using threading to test anomaly detection

import requests
import threading
import time
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter

# Request configuration
URL = "https://api.nexusmxp.com/api/documents"
PARAMS = {
    "page": "1",
    "limit": "6"
}
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

# Thread-safe counters
request_count = 0
success_count = 0
error_count = 0
status_codes = Counter()
lock = threading.Lock()


def make_request(request_id):
    """
    Makes a single HTTP request
    
    Args:
        request_id: Unique identifier for this request
        
    Returns:
        tuple: (request_id, success, status_code, error_message)
    """
    global request_count, success_count, error_count, status_codes
    
    try:
        response = requests.get(URL, params=PARAMS, headers=HEADERS, timeout=10)
        
        with lock:
            request_count += 1
            success_count += 1
            status_codes[response.status_code] += 1
            
        return (request_id, True, response.status_code, None)
        
    except requests.exceptions.RequestException as e:
        with lock:
            request_count += 1
            error_count += 1
            
        return (request_id, False, None, str(e))


def run_requests(num_requests=1000, num_threads=10):
    """
    Makes multiple HTTP requests using threading
    
    Args:
        num_requests: Total number of requests to make (default: 1000)
        num_threads: Number of concurrent threads (default: 10)
    """
    global request_count, success_count, error_count, status_codes
    
    # Reset counters
    request_count = 0
    success_count = 0
    error_count = 0
    status_codes = Counter()
    
    print(f"Starting {num_requests} requests with {num_threads} threads...")
    print(f"URL: {URL}")
    print(f"Params: {PARAMS}")
    print("-" * 60)
    
    start_time = time.time()
    
    # Use ThreadPoolExecutor to manage threads
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        # Submit all requests
        futures = [executor.submit(make_request, i) for i in range(num_requests)]
        
        # Process completed requests
        completed = 0
        for future in as_completed(futures):
            completed += 1
            if completed % 100 == 0:
                print(f"Progress: {completed}/{num_requests} requests completed")
    
    end_time = time.time()
    duration = end_time - start_time
    
    # Print results
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"Total Requests: {request_count}")
    print(f"Successful: {success_count}")
    print(f"Failed: {error_count}")
    print(f"Duration: {duration:.2f} seconds")
    print(f"Requests per second: {request_count / duration:.2f}")
    print(f"\nStatus Code Distribution:")
    for status_code, count in sorted(status_codes.items()):
        print(f"  {status_code}: {count}")


def main():
    """Main function with command-line argument parsing"""
    parser = argparse.ArgumentParser(
        description="Make HTTP requests to test anomaly detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python insolationForest.py                    # 1000 requests, 10 threads (default)
  python insolationForest.py -n 500             # 500 requests, 10 threads
  python insolationForest.py -t 20              # 1000 requests, 20 threads
  python insolationForest.py -n 2000 -t 50     # 2000 requests, 50 threads
        """
    )
    
    parser.add_argument(
        "-n", "--num-requests",
        type=int,
        default=1000,
        help="Number of requests to make (default: 1000)"
    )
    
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=10,
        help="Number of concurrent threads (default: 10)"
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.num_requests < 1:
        print("Error: Number of requests must be at least 1")
        return
    
    if args.threads < 1:
        print("Error: Number of threads must be at least 1")
        return
    
    # Run the requests
    run_requests(args.num_requests, args.threads)


if __name__ == "__main__":
    main()

