from flask import Flask, render_template, request, jsonify
import requests
import time
import dns.resolver
import concurrent.futures

app = Flask(__name__)

API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
DOMAINS_FILE = "domains.txt"
OUTPUT_FILE = "subdomains_output.txt"

# Function to fetch subdomains using the VirusTotal API
def fetch_subdomains(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    headers = {"x-apikey": API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            return [item["id"] for item in data.get("data", [])]
        else:
            return []
    except Exception as e:
        return []

# Function to get SPF record for a subdomain
def get_spf_record(subdomain):
    try:
        answers = dns.resolver.resolve(subdomain, 'TXT')
        for rdata in answers:
            txt_string = rdata.strings[0].decode('utf-8')
            if txt_string.startswith('v=spf'):
                return subdomain  # Return the subdomain if SPF record exists
        return None  # No SPF record found
    except Exception as e:
        return None  # Handle errors

# Route to display the home page
@app.route('/')
def index():
    return render_template('index.html')

# Route to handle form submission and run the subdomain check
@app.route('/check_subdomains', methods=['POST'])
def check_subdomains():
    domain = request.form['domain']
    subdomains = fetch_subdomains(domain)
    spf_results = []

    if subdomains:
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_subdomain = {executor.submit(get_spf_record, subdomain): subdomain for subdomain in subdomains}
            for future in concurrent.futures.as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    spf_results.append(result)
        return render_template('result.html', domain=domain, spf_results=spf_results)
    else:
        return render_template('result.html', domain=domain, spf_results=["No subdomains found."])

# Start the Flask app
if __name__ == '__main__':
    app.run(debug=True)
