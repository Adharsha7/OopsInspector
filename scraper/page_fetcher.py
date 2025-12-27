import requests

url = input("Enter website URL: ")

response = requests.get(url, timeout=10)

print("\nStatus Code:", response.status_code)
print("\n--- Response Headers ---")
for k, v in response.headers.items():
    print(f"{k}: {v}")
