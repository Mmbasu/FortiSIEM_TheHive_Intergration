import re
import xml.etree.ElementTree as ET
import json
from datetime import datetime, timezone


import re

def parse_cef(cef_line):
    """
    Parses a FortiSIEM CEF log line including prefix timestamp and IP, then parses the CEF content.
    Returns a dictionary with prefix and parsed CEF data (including rawEvent JSON).
    """
    # Extract prefix before the actual CEF string
    cef_start_index = cef_line.find("CEF:")
    if cef_start_index == -1:
        raise ValueError("No CEF section found in log line")

    prefix = cef_line[:cef_start_index].strip()  # Removes the datetime preceeding the CEF "May 14 14:19:36 10.254.1.2"
    cef_content = cef_line[cef_start_index:]     # "CEF: 0|Fortinet|..."

    # Regex to match CEF header and extensions
    cef_regex = re.compile(
        r'CEF:\s*(?P<version>\d+)\|(?P<deviceVendor>[^|]*)\|(?P<deviceProduct>[^|]*)\|(?P<deviceVersion>[^|]*)\|(?P<signatureID>[^|]*)\|(?P<name>[^|]*)\|(?P<severity>[^|]*)\|(?P<extensions>.*)'
    )

    match = cef_regex.match(cef_content.strip())
    if not match:
        raise ValueError("Invalid CEF format after prefix")

    cef_dict = match.groupdict()
    extension_str = cef_dict["extensions"]

    # Parse the extension fields including rawEvent
    raw_event_split = extension_str.split("rawEvent=", 1)

    ext_fields = {}
    raw_event_value = None

    if len(raw_event_split) == 2:
        before_raw_event = raw_event_split[0].strip()
        raw_event_value = raw_event_split[1].strip()

        for m in re.finditer(r'(\w+)=([^\s]+)', before_raw_event):
            key, value = m.group(1), m.group(2)
            ext_fields[key] = value

        ext_fields["rawEvent"] = raw_event_value
    else:
        for m in re.finditer(r'(\w+)=([^\s]+)', extension_str):
            key, value = m.group(1), m.group(2)
            ext_fields[key] = value

    cef_dict["extensions"] = ext_fields

    # Parse rawEvent (XML) into JSON
    if raw_event_value:
        print(f"Extracted rawEvent: {raw_event_value[:100]}...")
        parsed_raw_event = parse_raw_event(raw_event_value)
        cef_dict["rawEvent_json"] = parsed_raw_event
    else:
        print("No rawEvent field extracted!")
        cef_dict["rawEvent_json"] = {}

    # Return result including original prefix
    return {
        "prefix": prefix,
        "cef_data": cef_dict
    }




def parse_raw_event(raw_event_str):
    """Parses rawEvent by removing XML comments and using ElementTree to parse the valid XML"""
    raw_event_dict = {}

    # Remove all XML comments (not just the first one)
    raw_event_str = re.sub(r'<!--.*?-->', '', raw_event_str, flags=re.DOTALL).strip()

    if not raw_event_str:
        print("No rawEvent content to parse!")
        return {}

    print(f"Cleaned rawEvent string: {raw_event_str[:100]}...")  # Check the cleaned string

    # Make sure it's a valid XML: wrap in <root> if needed
    if not raw_event_str.startswith("<"):
        raw_event_str = "<root>" + raw_event_str + "</root>"

    try:
        # Parse the cleaned string into XML
        root = ET.fromstring(raw_event_str)  # Now it's wrapped in a root tag

        # Extract tag-value pairs from the XML
        for elem in root.iter():
            raw_event_dict[elem.tag] = elem.text.strip() if elem.text else ""

        print(f"Parsed rawEvent successfully: {raw_event_dict}")  # Debugging

    except ET.ParseError as e:
        print(f"Error parsing rawEvent XML: {e}")

    return raw_event_dict

def clean_prefix(prefix):
    """ Removes the last section (SIEM IP address) from the prefix string."""
    parts = prefix.strip().split()
    if len(parts) >= 4:
        return " ".join(parts[:-1])  # remove last element (IP)
    return prefix

def map_severity(fortisiem_sev):
    """ Maps FortiSIEM severity (0–10) to TheHive severity (1–4)."""
    try:
        sev = int(fortisiem_sev)
    except (TypeError, ValueError):
        return 2  # default to Medium if invalid

    if sev <= 4:
        return 1  # Low
    elif sev <= 7:
        return 2  # Medium
    elif sev <= 9:
        return 3  # High
    else:  # sev == 10
        return 4  # Critical


def create_alert(parsed_log):

    prefix = clean_prefix(parsed_log.get("prefix", ""))
    cef_event = parsed_log.get("cef_data", {})
    raw_event_data = cef_event.get("rawEvent_json", {})

    extensions = cef_event.get("extensions", {})
    source = f"{cef_event.get('deviceVendor', '')} - {cef_event.get('deviceProduct', '')}".strip(" -")

    source_ref = raw_event_data.get("incidentId", 1234)
    title = raw_event_data.get("_ruleName", "Unknown Event")
    description = raw_event_data.get("ruleDescription", "Default description")
    severity = map_severity(raw_event_data.get("eventSeverity", 2))

    event_time = prefix
    organization = extensions.get("cs2", "Default Organization")

    alert = {
        "title": title,
        "description": f"Alert Description: {description}",
        "type": "external",
        "source": source or "FortiSIEM",
        "sourceRef": source_ref,
        "severity": severity,
        "tlp": 2,
        "tags": organization,
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


if __name__ == "__main__":
    cef_event = parse_cef(
        'May 14 14:19:36 10.254.1.2 CEF: 0|Fortinet|FortiSIEM|ANY|1|PH_RULE_INAPPROPRIATE_WEB_TRAFFIC|5|cs1Label=SupervisorHostName cs1=fortisiem.is.co.ke cs2Label=CustomerName cs2=PREMIERCREDITUG cs3Label=IncidentDetail cs3=webCategory:Freeware and Software Downloads,  cs5Label=IncidentEventIDList cs5=4641522367539077482 cn1Label=CustomerID cn1=2010 cn2Label=IncidentID cn2=2068454 type=2 dvc=45.221.79.18 cnt=224 rt=1747221570 src=192.168.2.11 shost=HOST-192.168.2.11 rawEvent=<!-- PHBOX RULE ENGINE --><event name="phRuleIncident"><supervisorName>fortisiem.is.co.ke</supervisorName><deviceTime>1747221570</deviceTime><firstSeenTime>1746418920</firstSeenTime><count>224</count><durationMSec>600000</durationMSec><ruleId>937704</ruleId><_ruleName>Website access policy violation</_ruleName><ruleDescription>Network IPS or Security Gateway or Firewall detects inappropriate website access</ruleDescription><eventType>PH_RULE_INAPPROPRIATE_WEB_TRAFFIC</eventType><eventSeverity>5</eventSeverity><eventSeverityCat>MEDIUM</eventSeverityCat><phEventCategory>1</phEventCategory><phIncidentImpacts>Application</phIncidentImpacts><phIncidentCategory>Security</phIncidentCategory><phSubIncidentCategory>PH_RULE_SECURITY_Policy_Violation</phSubIncidentCategory><phCustId>2010</phCustId><incidentSrc>srcIpAddr:192.168.2.11, </incidentSrc><incidentTarget></incidentTarget><srcIpAddr>192.168.2.11</srcIpAddr><webCategory>Freeware and Software Downloads</webCategory><incidentDetail>webCategory:Freeware and Software Downloads, </incidentDetail><incidentRptIp>45.221.79.18</incidentRptIp><incidentRptDevName>Premier_Credit_FORTI</incidentRptDevName><incidentRptGeoCountry>Uganda</incidentRptGeoCountry><incidentRptGeoCountryCodeStr>UG</incidentRptGeoCountryCodeStr><incidentRptGeoState>Central</incidentRptGeoState><incidentRptGeoCity>Kampala</incidentRptGeoCity><incidentRptGeoOrg>SIMBANET-AS  TZ</incidentRptGeoOrg><incidentRptGeoLatitude>0.3476</incidentRptGeoLatitude><incidentRptGeoLongitude>32.58252</incidentRptGeoLongitude><triggerEventLists><triggerEvents subpatName="WebViolation">4641522367539077482</triggerEvents><triggerEventTypes subpatName="WebViolation">FortiGate-event-dns-ftgd-cat-block</triggerEventTypes></triggerEventLists><incidentId>2068454</incidentId></event>')

    with open(r"C:\Users\Muhanji\Documents\parsed_output.txt", "w") as output:
        output.write(json.dumps(cef_event, indent=2))

    alert = create_alert(cef_event)

    with open(r"C:\Users\Muhanji\Documents\alert_output.txt", "w") as output:
        output.write(json.dumps(alert, indent=2))
