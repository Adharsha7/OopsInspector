import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

url = input("Enter website URL: ")

try:
    response = requests.get(url, timeout=15)
except requests.exceptions.RequestException as e:
    print("\n[!] Connection error:", e)
    exit()

soup = BeautifulSoup(response.text, "html.parser")

print("\n--- Discovered Links ---")

links = set()

for tag in soup.find_all("a"):
    href = tag.get("href")
    if href:
        full_url = urljoin(url, href)
        links.add(full_url)

for link in links:
    print(link)

