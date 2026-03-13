import requests
from bs4 import BeautifulSoup

url = input("Enter target URL (e.g., http://example.com): ")
response = requests.get(url)
soup = BeautifulSoup(response.text, 'html.parser')

for link in soup.find_all('a'):
    href = link.get('href')
    if href:
        print(href)
