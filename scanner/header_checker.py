import requests

url = input("Enter website URL: ")

response = requests.get(url, timeout=10)

required_headers = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy"
]

print("\n--- Security Header Report ---")

for header in required_headers:
    if header in response.headers:
        print(f"[OK] {header}")
    else:
        print(f"[MISSING] {header}")
