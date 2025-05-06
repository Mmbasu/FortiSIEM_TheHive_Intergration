from datetime import datetime, timedelta
import json
import requests
import logging
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Logging setup(Initializes Logging for status/debug info)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration(Loading sensitive credentials from .env)
FSIEM_URL = os.getenv('FSIEM_URL')
FSIEM_USERNAME = os.getenv('FSIEM_USERNAME')
FSIEM_PASSWORD = os.getenv('FSIEM_PASSWORD')

THEHIVE_URL = os.getenv('THEHIVE_URL')
THEHIVE_API_KEY = os.getenv('THEHIVE_API_KEY')


def authenticate_fortisiem():
    """Authenticate to FortiSIEM and return an authenticated session
    if all the FortiSIEM Credentials are present in the .env file
    """
    if not all([FSIEM_URL, FSIEM_USERNAME, FSIEM_PASSWORD]):
        raise ValueError("FortiSIEM credentials are missing in .env")

    session = requests.Session()
    #Sends a post request to the fortisiem api endpoint to start an authenticated session
    response = session.post(
        f"{FSIEM_URL}/phoenix/rest/login",
        json={"username": FSIEM_USERNAME, "password": FSIEM_PASSWORD},
        timeout=10,
        verify=True
    )
    response.raise_for_status()
    logging.info("Authenticated with FortiSIEM.")
    #Returns a request.Session object with valid token for future API Calls
    return session

def fetch_events(session):
    """Fetch high-severity events from FortiSIEM."""
    now = datetime.utcnow()
    ten_minutes_ago = now - timedelta(minutes=10)
    #Sends a JSON payload to fetch high-severity events (eventSeverity > 3)
    #Time range is set at last 10 mins and the query has a limit of 10 events returned
    payload = {
        "timeRange": {
            "startTime": ten_minutes_ago.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "endTime": now.strftime("%Y-%m-%dT%H:%M:%SZ")
        },
        "reportContent": {
            "query": "SELECT * FROM event WHERE eventSeverity > 3 LIMIT 10"
        }
    }

    response = session.post(
        f"{FSIEM_URL}/phoenix/rest/report/adHocReport",
        json=payload,
        timeout=15
    )
    response.raise_for_status()
    return response.json().get("rows", [])

def create_alert(event):
    """Create a properly structured alert for TheHive."""
    title = f"FortiSIEM Alert: {event.get('eventType', 'Unknown')}"
    alert = {
        "title": title,
        "description": f"Event from FortiSIEM:\n\n{json.dumps(event, indent=2)}",
        "type": "external",
        "source": "FortiSIEM",
        "sourceRef": str(event.get("eventID", str(datetime.utcnow().timestamp()))),
        "severity": min(int(event.get("eventSeverity", 2)) * 25, 100),
        "tlp": 2,
        "tags": [event.get("eventType", "Unknown"), str(event.get("reporter", ""))],
        "observables": []
    }

    for ip_key in ["srcIP", "dstIP"]:
        ip = event.get(ip_key)
        if ip:
            alert["observables"].append({
                "dataType": "ip",
                "data": ip,
                "message": f"{ip_key} of the event"
            })

    return alert

def send_to_thehive(alert):
    """Send alert to TheHive after checking that the required credentials are present in the .env file"""
    if not all([THEHIVE_URL, THEHIVE_API_KEY]):
        raise ValueError("TheHive credentials are missing in .env")

    headers = {
        "Authorization": f"Bearer {THEHIVE_API_KEY}",
        "Content-Type": "application/json"
    }
    response = requests.post(f"{THEHIVE_URL}/api/alert", headers=headers, json=alert, timeout=10)

    #Log success or failure and also handles duplicates (409 responses) gracefully.
    if response.status_code == 201:
        logging.info(f"Alert '{alert['title']}' sent to TheHive.")
    elif response.status_code == 409:
        logging.warning(f"Duplicate alert '{alert['title']}' detected (sourceRef conflict).")
    else:
        logging.error(f"Failed to send alert to TheHive: {response.text}")
        response.raise_for_status()

def main():
    """Ties it all together
    1. Authenticates with fortisiem and returns a session
    2. Fetches events using session as an argument and returns events
    3. Checks if events returned actually has data.
    4. Returns properly structured alerts for TheHive using the events returned as arguments
    5. Sends the alerts to the hive and handles any exception errors
    
    """
    try:
        session = authenticate_fortisiem()
        events = fetch_events(session)
        if not events:
            logging.info("No new high-severity events found.")
        for event in events:
            alert = create_alert(event)
            send_to_thehive(alert)
    except requests.RequestException as e:
        logging.error(f"Network/API error: {e}")
    except Exception as e:
        logging.exception(f"Unhandled exception: {e}")

if __name__ == "__main__":
    main()
