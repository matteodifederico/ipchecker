from datetime import datetime, timezone
from tabulate import tabulate
import sys
import os
import requests

OTX_API_KEY = os.getenv("IPCHECKER_OTX_API_KEY", None)
VIRUSTOTAL_API_KEY = os.getenv("IPCHECKER_VIRUSTOTAL_API_KEY", None)

def ip_lookup(ip):
    print(r"""
          
        ___ ____    _                _                
       |_ _|  _ \  | |    ___   ___ | | ___   _ _ __  
        | || |_) | | |   / _ \ / _ \| |/ / | | | '_ \ 
        | ||  __/  | |__| (_) | (_) |   <| |_| | |_) |
       |___|_|     |_____\___/ \___/|_|\_\\__,_| .__/ 
                                               |_|    
    """)
    url_ip_lookup = f"https://app-devbox-security-prod-westeurope.azurewebsites.net/net/ip/lookup?ip={ip}"
    headers_ip_lookup = {
        "accept": "application/json"
    }
    
    response_ip_lookup = requests.get(url_ip_lookup, headers=headers_ip_lookup, timeout=10)
    if response_ip_lookup.status_code == 200:
        data = response_ip_lookup.json()
        #print(json.dumps(data, indent=4))
        
        if data.get("success"):
            print("🔎  Found IP Information:")
            #write upper info in object
            ip_info = {
                "IP": data['ip'],
                "Country": data['country'],
                "Region": data['region'],
                "City": data['city'],
                "Postal Code": data['postal'],
                "Latitude": data['latitude'],
                "Longitude": data['longitude'],
                "Continent": data['continent'],
                "Timezone": f"{data['timezone']['id']} (UTC{data['timezone']['utc']})",
                "Calling Code": data['calling_code'],
                "Capital": data['capital'],
                "Borders": data['borders'] if data.get('borders') else 'None',
                "Flag": f"{data['flag']['emoji']} ({data['flag']['emoji_unicode']})",
                "ASN": data['connection']['asn'],
                "ISP": data['connection']['isp'],
                "Related Domain": data['connection']['domain'],
                "Organization": data['connection']['org'],
                "Is EU": 'Yes' if data['is_eu'] else 'No'
            }
            table_data = [(key, value) for key, value in ip_info.items()]
            print(tabulate(table_data, tablefmt="grid"))
        else:
            print("⚠️  No information found for the provided IP address.")
    else:
        print(f"Error during the IP lookup: {response_ip_lookup.status_code}")

def check_otx(ip):
    if OTX_API_KEY is None:
        print("⚠️  OTX API Key not found. Please set the IPCHECKER_OTX_API_KEY environment variable.")
        return
    
    print(r"""
          
        _    _ _         __     __          _ _      ___ _______  __
       / \  | (_) ___ _ _\ \   / /_ _ _   _| | |_   / _ \_   _\ \/ /
      / _ \ | | |/ _ \ '_ \ \ / / _` | | | | | __| | | | || |  \  / 
     / ___ \| | |  __/ | | \ V / (_| | |_| | | |_  | |_| || |  /  \ 
    /_/   \_\_|_|\___|_| |_|\_/ \__,_|\__,_|_|\__|  \___/ |_| /_/\_\
    """)
    url_otx = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers_otx = {
        "X-OTX-API-KEY": OTX_API_KEY
    }
    
    response_otx = requests.get(url_otx, headers=headers_otx)
    if response_otx.status_code == 200:
        data = response_otx.json()
        #print(json.dumps(data, indent=4))
        
        if "pulse_info" in data:
            print("⚠️  Found Feed on AlienVault OTX:")
            print("")
            pulses = data["pulse_info"]["pulses"]
            for pulse in pulses:
                print(f"\n+------ 👽 Pulse Name: {pulse['name']}")
                print(f"|  - Description: {pulse['description']}")
                print(f"|  - Created: {pulse['created']}")
                print(f"|  - Modified: {pulse['modified']}")
                print(f"|  - Tags: {', '.join(pulse['tags']) if pulse['tags'] else 'No Tags'}")
                print(f"|  - Targeted Countries: {', '.join(pulse['targeted_countries']) if pulse['targeted_countries'] else 'None'}")
                print(f"|  - Industries: {', '.join(pulse['industries']) if pulse['industries'] else 'None'}")
                print(f"|  - References: {', '.join(pulse['references']) if pulse['references'] else 'None'}")
                print(f"|  - Pulse Source: {pulse['pulse_source']}")
                print(f"|  - Threat Level: {pulse['TLP']}")
                print(f"+------ End of Pulse")
        else:
            print("✅  No correlated threat found on AlienVault OTX.")
    else:
        print(f"Error during the search on AlienVault OTX: {response_otx.status_code}")

def check_virustotal(ip):
    if VIRUSTOTAL_API_KEY is None:
        print("⚠️  VirusTotal API Key not found. Please set the IPCHECKER_VIRUSTOTAL_API_KEY environment variable.")
        return
    
    print(r"""
          
    __     ___                  _____     _        _ 
    \ \   / (_)_ __ _   _ ___  |_   _|__ | |_ __ _| |
     \ \ / /| | '__| | | / __|   | |/ _ \| __/ _` | |
      \ V / | | |  | |_| \__ \   | | (_) | || (_| | |
       \_/  |_|_|   \__,_|___/   |_|\___/ \__\__,_|_|
    """)
    url_virustotal = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers_virustotal = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    
    response_virustotal = requests.get(url_virustotal, headers=headers_virustotal)
    if response_virustotal.status_code == 200:
        data = response_virustotal.json()
        #print(json.dumps(data, indent=4)) 

        if 'data' in data and 'attributes' in data['data']:
            attributes = data['data']['attributes']
            print(f"⚠️  Found Feed on VirusTotal:")
            vt_info = {
                "Country": attributes['country'],
                "ASN": attributes['asn'],
                "WHOIS": attributes['whois'],
                "Continent": attributes['continent'],
                "Network": attributes['network'],
                "Reputation": attributes['reputation'],
                "Tags": ', '.join(attributes['tags']) if attributes['tags'] else 'No Tags'
            }
            table_data = [(key, value) for key, value in vt_info.items()]
            print(tabulate(table_data, tablefmt="grid"))

            print("\n+------- 🧪 Security engine analysis results:")
            for engine, result in attributes['last_analysis_results'].items():
                print(f"|  - {engine}: {result['result']} ({result['category']})")
            print(f"+------- End of Security engine analysis results")
            
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            print("\n📈  Analysis statistics:")
            #convert prevous data in a table
            table_data = [
                ["Malicious", last_analysis_stats.get('malicious', 0)],
                ["Suspicious", last_analysis_stats.get('suspicious', 0)],
                ["Undetected", last_analysis_stats.get('undetected', 0)],
                ["Harmless", last_analysis_stats.get('harmless', 0)],
                ["Timeout", last_analysis_stats.get('timeout', 0)]
            ]
            print(tabulate(table_data, headers=["Result", "Count"], tablefmt="grid"))


            
        else:
            print("✅  No correlated threat found on Virus Total.")
    else:
        print(f"Error during the search on VirusTotal: {response_virustotal.status_code}")

if __name__ == "__main__":
    print(r"""
     /$$$$$$ /$$$$$$$   /$$$$$$  /$$                           /$$                          
    |_  $$_/| $$__  $$ /$$__  $$| $$                          | $$                           
      | $$  | $$  \\ $$| $$  \\__/| $$$$$$$   /$$$$$$   /$$$$$$$| $$   /$$  /$$$$$$   /$$$$$$ 
      | $$  | $$$$$$$/| $$      | $$__  $$ /$$__  $$ /$$_____/| $$  /$$/ /$$__  $$ /$$__  $$ 
      | $$  | $$____/ | $$      | $$  \\ $$| $$$$$$$$| $$      | $$$$$$/ | $$$$$$$$| $$  \\__/ 
      | $$  | $$      | $$    $$| $$  | $$| $$_____/| $$      | $$_  $$ | $$_____/| $$       
     /$$$$$$| $$      |  $$$$$$/| $$  | $$|  $$$$$$$|  $$$$$$$| $$ \\  $$|  $$$$$$$| $$      
    |______/|__/       \\______/ |__/  |__/ \\_______/ \\_______/|__/  \\__/ \\_______/|__/      
    """)
    print("""
    @author: Matteo Di Federico
    @tags: #ip #otx #virustotal
        
          """)
    if len(sys.argv) != 2:
        print("Usage: python ipchecker.py <IPV4_ADDRESS>")
        sys.exit(1)
    
    ip_address = sys.argv[1]
    
    try:
        parts = ip_address.split(".")
        if len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts):
            now = datetime.now(timezone.utc).timestamp()
            timestamp = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            print(f"🚀 {timestamp} UTC ==> Verification for the IP: {ip_address}")
            ip_lookup(ip_address)
            check_otx(ip_address)
            check_virustotal(ip_address)
        else:
            raise ValueError("Invalid IP address.")
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)