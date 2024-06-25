import requests

# Replace with your Gemini API endpoint and authentication method
GEMINI_API_URL = "https://example.com/gemini/api"
API_KEY = "AIzaSyBe0LN24yf1rycY0LXkqlCPYDZeCdOVaKo"

def search_cve_ids(keyword):
    url = f"{GEMINI_API_URL}/cve/search"
    headers = {
        'Authorization': f'Bearer {API_KEY}',
        'Content-Type': 'application/json'
    }
    params = {
        'keyword': keyword
    }
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()  # Raise an exception for HTTP errors
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error searching CVE IDs: {e}")
        return None

# Example usage
if __name__ == "__main__":
    keyword = "IoT vulnerabilities"  # Replace with your search keyword
    cve_data = search_cve_ids(keyword)
    if cve_data:
        print("CVE IDs found:")
        for cve in cve_data['cve_ids']:
            print(cve)
