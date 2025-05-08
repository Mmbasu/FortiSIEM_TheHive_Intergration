import socketserver
import logging
import json
import os
import re
import requests
from datetime import datetime, timezone
from dotenv import load_dotenv

# Configuration(Loading environment variables)
load_dotenv()

THEHIVE_URL = os.getenv("THEHIVE_URL")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY")

# Logging setup(Initializes Logging for status/debug info)
logging.basicConfig(
    filename="cef_to_thehive.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)


def parse_cef(cef_line):
    """Parses FortiSIEM’s CEF log line into structured fields"""
    cef_regex = re.compile(
        r'CEF:(?P<version>\d+)\|(?P<deviceVendor>[^|]*)\|(?P<deviceProduct>[^|]*)\|(?P<deviceVersion>[^|]*)\|(?P<signatureID>[^|]*)\|(?P<name>[^|]*)\|(?P<severity>[^|]*)\|(?P<extensions>.*)')
    # Applies the regex to the string and returns a Match object if it exists
    match = cef_regex.match(cef_line.strip())
    if not match:
        raise ValueError("Invalid CEF format")

    # Converts the named groups from the regex into a Python dictionary
    cef_dict = match.groupdict()
    ext_fields = {}

    # Processes the extensions section, which contains space-separated key=value pairs.
    for pair in cef_dict["extensions"].split():
        if '=' in pair:
            k, v = pair.split('=', 1)
            ext_fields[k] = v

    # Replaces the raw string in "extensions" with a structured dictionary of parsed fields
    cef_dict["extensions"] = ext_fields
    return cef_dict

def create_alert(cef_event):
    """Converts parsed CEF data into a format TheHive understands"""
    extensions = cef_event.get("extensions", {})
    title = cef_event.get("name", "Unknown Event")
    source = f"{cef_event.get('deviceVendor', '')} - {cef_event.get('deviceProduct', '')}".strip(" -")
    severity = int(cef_event.get("severity", 2))
    source_ref = cef_event.get("signatureID", str(datetime.now(timezone.utc).timestamp()))
    description = cef_event.get("rawEvent") or json.dumps(cef_event, indent=2)
    event_time = extensions.get("start", datetime.now(timezone.utc).isoformat())

    alert = {
        "title": title,
        "description": f"CEF Event Details:\n\n{description}",
        "type": "external", # always
        "source": source or "FortiSIEM",
        "sourceRef": source_ref,
        "severity": min(max((severity + 1), 1), 4), # Look into FortiSIEM severity scale vs The Hive's
        "tlp": 2, # set to green by default
        "tags": extensions.get("tags", "fortisiem").split(','),
        "observables": [],
        "date": event_time
    }

    for field, role in [("src", "Source IP"), ("dst", "Destination IP")]:
        ip = extensions.get(field)
        if ip:
            alert["observables"].append({
                "dataType": "ip",
                "data": ip,
                "message": f"{role}"
            })

    for field, role in [("suser", "Source User"), ("duser", "Destination User")]:
        user = extensions.get(field)
        if user:
            alert["observables"].append({
                "dataType": "user",
                "data": user,
                "message": f"{role}"
            })

    for geo_field in ["srcGeo", "dstGeo"]:
        geo = extensions.get(geo_field)
        if geo:
            alert["observables"].append({
                "dataType": "other",
                "data": geo,
                "message": f"{geo_field} location"
            })

    return alert

def send_to_thehive(alert):
    """Send alert to TheHive after checking that the required credentials are present in the .env file"""
    if not THEHIVE_URL or not THEHIVE_API_KEY:
        logging.error("Missing TheHive configuration in environment variables.")
        return

    headers = {
        "Authorization": f"Bearer {THEHIVE_API_KEY}",
        "Content-Type": "application/json"
    }

    # Log success or failure and also handles duplicates (409 responses) gracefully.
    try:
        response = requests.post(f"{THEHIVE_URL}/api/alert", headers=headers, json=alert, timeout=10)
        if response.status_code == 201:
            logging.info(f"Alert '{alert['title']}' successfully sent to TheHive.")
        elif response.status_code == 409:
            logging.warning(f"Duplicate alert '{alert['title']}' detected.")
        else:
            logging.error(f"TheHive API returned error: {response.status_code} {response.text}")
    except requests.RequestException as e:
        logging.error(f"Failed to send alert to TheHive: {str(e)}")

def handle_syslog(data):
    try:
        cef_event = parse_cef(data)
        logging.info(f"Parsed CEF event: {cef_event.get('name', 'Unknown')}")
        alert = create_alert(cef_event)
        send_to_thehive(alert)
    except Exception as e:
        logging.error(f"Failed to parse/send event: {str(e)}")

class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0].strip().decode("utf-8", errors="ignore")
        handle_syslog(data)

if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 5140
    with socketserver.UDPServer((HOST, PORT), SyslogUDPHandler) as server:
        logging.info(f"CEF Syslog listener started on {HOST}:{PORT}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            logging.info("CEF listener shutting down.")
