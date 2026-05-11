import time
import os, requests
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
import ipaddress
import certifi

print("Initializing Threat Intelligence Module...")
time.sleep(1)
print("Loading API keys and configurations...")
time.sleep(1)
print("Ready to analyze IP addresses for potential threats.")
print("\n")  # Add spacing before input prompt

print("Input your IP address to check for threats:")
load_dotenv()
console = Console()

VT_API_KEY = os.getenv("VT_API")
ABUSE_API_KEY = os.getenv("ABUSE_API")
IP_INFO_API_KEY = os.getenv("IP_INFO_API")


def validar_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
    

    
    

def check_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers, verify=certifi.where())
    data = response.json()["data"]["attributes"]
    stats = data.get("last_analysis_stats", {})
    return{
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "reputation": data.get("reputation", 0)
    }


def check_abuseipdb(ip):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
    response = requests.get(url, headers=headers, verify=certifi.where())
    data = response.json().get("data", {})
    return{
        "abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
        "totalReports": data.get("totalReports", 0)
    }
    
def check_ipinfo(ip):
    url = f"https://ipinfo.io/{ip}/json?token={IP_INFO_API_KEY}"
    response = requests.get(url, verify=certifi.where())
    data = response.json()
    return{
        "country": data.get("country", "N/A"),
        "org": data.get("org", "N/A")
    }
    
def print_kv(ip, vt, abuse, ipinfo):
    def safe(d, k):
        return d.get(k, "N/A") if isinstance(d, dict) else "N/A"

    print(f"ip={ip}")

    # VirusTotal
    print(f"malicious={safe(vt, 'malicious')}")
    print(f"suspicious={safe(vt, 'suspicious')}")
    print(f"reputation={safe(vt, 'reputation')}")

    # AbuseIPDB
    print(f"abuse_confidence={safe(abuse, 'abuseConfidenceScore')}%")
    print(f"abuse_reports={safe(abuse, 'totalReports')}")

    # IPinfo
    print(f"country={safe(ipinfo, 'country')}")
    print(f"organization={safe(ipinfo, 'org')}")

ip_address = ""

while(ip_address != "0"):
    ip_address = input(str("IP Address or 0 to quit: "))
    if not validar_ip(ip_address):
        print("Invalid IP address. Please try again.")
        continue
    if ip_address == "0":
        print("Exiting Threat Intelligence Module. Stay safe!")
        break
    vt_result = check_virustotal(ip_address)
    abuse_result = check_abuseipdb(ip_address)  
    ipinfo_result = check_ipinfo(ip_address)
    table = Table(title=f"Threat Intelligence for {ip_address}")
    table.add_column("Source", style="cyan", no_wrap=True)  
    table.add_column("Malicious", style="red")
    table.add_column("Suspicious", style="yellow")
    table.add_column("Reputation", style="green")
    table.add_column("Abuse Score", style="magenta")
    table.add_column("Total Reports", style="magenta")
    table.add_column("Country", style="blue")
    table.add_column("Organization", style="blue")
    table.add_row(
        "VirusTotal",
        str(vt_result["malicious"]),
        str(vt_result["suspicious"]),
        str(vt_result["reputation"]),
        str(abuse_result["abuseConfidenceScore"]),
        str(abuse_result["totalReports"]),
        ipinfo_result["country"],
        ipinfo_result["org"]
    )
    
    console.print(table)
    print("\n")  # Add spacing between entries
    print("Copy and paste version: ")
    print("\n")  # Add spacing between entries
    print_kv(ip_address, vt_result, abuse_result, ipinfo_result)
    print("\n")  # Add spacing between entries
    print("--- End of Report ---")
    print("\n")  # Add spacing between entries