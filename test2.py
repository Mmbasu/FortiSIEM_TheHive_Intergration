import re
import xml.etree.ElementTree as ET
import json
from datetime import datetime, timezone


import re

def parse_cef(cef_line):
    """Parses FortiSIEM’s CEF log line into structured fields, and parses rawEvent into JSON"""
    cef_regex = re.compile(
        r'CEF:\s*(?P<version>\d+)\|(?P<deviceVendor>[^|]*)\|(?P<deviceProduct>[^|]*)\|(?P<deviceVersion>[^|]*)\|(?P<signatureID>[^|]*)\|(?P<name>[^|]*)\|(?P<severity>[^|]*)\|(?P<extensions>.*)'
    )

    match = cef_regex.match(cef_line.strip())
    if not match:
        raise ValueError("Invalid CEF format")

    cef_dict = match.groupdict()
    extension_str = cef_dict["extensions"]

    # Handle rawEvent separately to avoid breaking on embedded '='
    raw_event_split = extension_str.split("rawEvent=", 1)

    ext_fields = {}
    raw_event_value = None

    if len(raw_event_split) == 2:
        before_raw_event = raw_event_split[0].strip()
        raw_event_value = raw_event_split[1].strip()

        # Parse key=value pairs before rawEvent
        for m in re.finditer(r'(\w+)=([^\s]+)', before_raw_event):
            key, value = m.group(1), m.group(2)
            ext_fields[key] = value

        ext_fields["rawEvent"] = raw_event_value
    else:
        # No rawEvent — parse entire extension string normally
        for m in re.finditer(r'(\w+)=([^\s]+)', extension_str):
            key, value = m.group(1), m.group(2)
            ext_fields[key] = value

    cef_dict["extensions"] = ext_fields

    # Parse rawEvent XML into JSON if available
    if raw_event_value:
        print(f"Extracted rawEvent: {raw_event_value[:100]}...")
        parsed_raw_event = parse_raw_event(raw_event_value)
        cef_dict["rawEvent_json"] = parsed_raw_event
    else:
        print("No rawEvent field extracted!")
        cef_dict["rawEvent_json"] = {}

    return cef_dict




def parse_raw_event(raw_event_str):
    """Parses rawEvent by removing XML comments and using ElementTree to parse the valid XML"""
    raw_event_dict = {}

    # Remove all XML comments (not just the first one)
    raw_event_str = re.sub(r'<!--.*?-->', '', raw_event_str, flags=re.DOTALL).strip()

    if not raw_event_str:
        print("No rawEvent content to parse!")
        return {}

    # Debugging step: Print the cleaned raw_event_str
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


def create_alert(cef_event):
    """Converts parsed CEF data into a format TheHive understands"""
    extensions = cef_event.get("extensions", {})
    title = cef_event.get("name", "Unknown Event")
    source = f"{cef_event.get('deviceVendor', '')} - {cef_event.get('deviceProduct', '')}".strip(" -")
    severity = int(cef_event.get("severity", 2))

    # Try to use incidentId from the parsed rawEvent JSON as sourceRef
    raw_event_data = cef_event.get("rawEvent_json", {})
    source_ref = raw_event_data.get("incidentId") or cef_event.get("signatureID", str(datetime.now(timezone.utc).timestamp()))


    description = json.dumps(cef_event.get("rawEvent_json", {}), indent=2)
    event_time = extensions.get("rt", datetime.now(timezone.utc).isoformat())

    alert = {
        "title": title,
        "description": f"CEF Event Details:\n\n{description}",
        "type": "external",
        "source": source or "FortiSIEM",
        "sourceRef": source_ref,
        "severity": min(max((severity + 1), 1), 4),
        "tlp": 2,
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


if __name__ == "__main__":
    cef_event = parse_cef(
        'CEF: 0|Fortinet|FortiSIEM|ANY|1|PH_RULE_INAPPROPRIATE_WEB_TRAFFIC|5|cs1Label=SupervisorHostName cs1=fortisiem.is.co.ke cs2Label=CustomerName cs2=PREMIERCREDITUG cs3Label=IncidentDetail cs3=webCategory:Freeware and Software Downloads,  cs5Label=IncidentEventIDList cs5=4641522367539077482 cn1Label=CustomerID cn1=2010 cn2Label=IncidentID cn2=2068454 type=2 dvc=45.221.79.18 cnt=224 rt=1747221570 src=192.168.2.11 shost=HOST-192.168.2.11 rawEvent=<!-- PHBOX RULE ENGINE --><event name="phRuleIncident"><supervisorName>fortisiem.is.co.ke</supervisorName><deviceTime>1747221570</deviceTime><firstSeenTime>1746418920</firstSeenTime><count>224</count><durationMSec>600000</durationMSec><ruleId>937704</ruleId><_ruleName>Website access policy violation</_ruleName><ruleDescription>Network IPS or Security Gateway or Firewall detects inappropriate website access</ruleDescription><eventType>PH_RULE_INAPPROPRIATE_WEB_TRAFFIC</eventType><eventSeverity>5</eventSeverity><eventSeverityCat>MEDIUM</eventSeverityCat><phEventCategory>1</phEventCategory><phIncidentImpacts>Application</phIncidentImpacts><phIncidentCategory>Security</phIncidentCategory><phSubIncidentCategory>PH_RULE_SECURITY_Policy_Violation</phSubIncidentCategory><phCustId>2010</phCustId><incidentSrc>srcIpAddr:192.168.2.11, </incidentSrc><incidentTarget></incidentTarget><srcIpAddr>192.168.2.11</srcIpAddr><webCategory>Freeware and Software Downloads</webCategory><incidentDetail>webCategory:Freeware and Software Downloads, </incidentDetail><incidentRptIp>45.221.79.18</incidentRptIp><incidentRptDevName>Premier_Credit_FORTI</incidentRptDevName><incidentRptGeoCountry>Uganda</incidentRptGeoCountry><incidentRptGeoCountryCodeStr>UG</incidentRptGeoCountryCodeStr><incidentRptGeoState>Central</incidentRptGeoState><incidentRptGeoCity>Kampala</incidentRptGeoCity><incidentRptGeoOrg>SIMBANET-AS  TZ</incidentRptGeoOrg><incidentRptGeoLatitude>0.3476</incidentRptGeoLatitude><incidentRptGeoLongitude>32.58252</incidentRptGeoLongitude><triggerEventLists><triggerEvents subpatName="WebViolation">4641522367539077482</triggerEvents><triggerEventTypes subpatName="WebViolation">FortiGate-event-dns-ftgd-cat-block</triggerEventTypes></triggerEventLists><incidentId>2068454</incidentId></event>')

    print(f"CEF after parse: {cef_event}")
    alert = create_alert(cef_event)

    with open(r"C:\Users\Muhanji\Documents\output.txt", "w") as output:
        output.write(json.dumps(alert, indent=2))



    """print(f"Parsed CEF Event: {cef_event}")

    # Extract rawEvent and parse it
    raw_event = cef_event.get("extensions", {}).get("rawEvent", "")
    if raw_event:
        raw_event_json = parse_raw_event(raw_event)
        print(f"Raw Event JSON: {json.dumps(raw_event_json, indent=2)}")
    else:
        print("No rawEvent found!")"""
