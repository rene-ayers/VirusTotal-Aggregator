import requests
import json
import time

# Replace with your actual VirusTotal API Key
VIRUSTOTAL_API_KEY = "[YOUR_API_KEY]"

# Function to query VirusTotal for IP reputation
def check_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        return parse_virustotal_response(data)
    
    return {"error": f"Failed to fetch data. Status Code: {response.status_code}"}

# Function to extract key threat intelligence data from VirusTotal response
def parse_virustotal_response(data):
    attributes = data.get("data", {}).get("attributes", {})
    
    # Extracting useful fields
    last_analysis_stats = attributes.get("last_analysis_stats", {})
    last_analysis_date = attributes.get("last_analysis_date", "N/A")
    total_votes = attributes.get("total_votes", {})

    # Returning formatted report
    return {
        "last_analysis_stats": last_analysis_stats,
        "last_analysis_date": last_analysis_date,
        "total_votes": total_votes,
        "whois": attributes.get("whois", "N/A"),
        "country": attributes.get("country", "N/A"),
        "reputation_score": attributes.get("reputation", "N/A")
    }

# Function to generate and display the report
def generate_report(ip):
    print(f"\nFetching VirusTotal report for: {ip}\n")
    time.sleep(5) # Processing delay

    report = check_virustotal(ip)

    print("--- VirusTotal Threat Intelligence Report ---\n")
    print(json.dumps(report, indent=4))

# User input for IP address
if __name__ == "__main__":
    target_ip = input("Enter an IP address to analyze: ")
    generate_report(target_ip)
