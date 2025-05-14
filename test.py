import json
import re
from datetime import datetime, timezone


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

if __name__ == "__main__":
    cef_event = parse_cef('CEF: 0|Fortinet|FortiSIEM|ANY|1|PH_RULE_INAPPROPRIATE_WEB_TRAFFIC|5|cs1Label=SupervisorHostName cs1=fortisiem.is.co.ke cs2Label=CustomerName cs2=PREMIERCREDITUG cs3Label=IncidentDetail cs3=webCategory:Freeware and Software Downloads,  cs5Label=IncidentEventIDList cs5=4641522367539077482 cn1Label=CustomerID cn1=2010 cn2Label=IncidentID cn2=2068454 type=2 dvc=45.221.79.18 cnt=224 rt=1747221570 src=192.168.2.11 shost=HOST-192.168.2.11 rawEvent=<!-- PHBOX RULE ENGINE --><event name="phRuleIncident"><supervisorName>fortisiem.is.co.ke</supervisorName><deviceTime>1747221570</deviceTime><firstSeenTime>1746418920</firstSeenTime><count>224</count><durationMSec>600000</durationMSec><ruleId>937704</ruleId><_ruleName>Website access policy violation</_ruleName><ruleDescription>Network IPS or Security Gateway or Firewall detects inappropriate website access</ruleDescription><eventType>PH_RULE_INAPPROPRIATE_WEB_TRAFFIC</eventType><eventSeverity>5</eventSeverity><eventSeverityCat>MEDIUM</eventSeverityCat><phEventCategory>1</phEventCategory><phIncidentImpacts>Application</phIncidentImpacts><phIncidentCategory>Security</phIncidentCategory><phSubIncidentCategory>PH_RULE_SECURITY_Policy_Violation</phSubIncidentCategory><phCustId>2010</phCustId><incidentSrc>srcIpAddr:192.168.2.11, </incidentSrc><incidentTarget></incidentTarget><srcIpAddr>192.168.2.11</srcIpAddr><webCategory>Freeware and Software Downloads</webCategory><incidentDetail>webCategory:Freeware and Software Downloads, </incidentDetail><incidentRptIp>45.221.79.18</incidentRptIp><incidentRptDevName>Premier_Credit_FORTI</incidentRptDevName><incidentRptGeoCountry>Uganda</incidentRptGeoCountry><incidentRptGeoCountryCodeStr>UG</incidentRptGeoCountryCodeStr><incidentRptGeoState>Central</incidentRptGeoState><incidentRptGeoCity>Kampala</incidentRptGeoCity><incidentRptGeoOrg>SIMBANET-AS  TZ</incidentRptGeoOrg><incidentRptGeoLatitude>0.3476</incidentRptGeoLatitude><incidentRptGeoLongitude>32.58252</incidentRptGeoLongitude><triggerEventLists><triggerEvents subpatName="WebViolation">4641522367539077482</triggerEvents><triggerEventTypes subpatName="WebViolation">FortiGate-event-dns-ftgd-cat-block</triggerEventTypes></triggerEventLists><incidentId>2068454</incidentId></event>')
    print(cef_event)
    alert = create_alert(cef_event)

    with open(r"C:\Users\Muhanji\Documents\output.txt", "w") as output:
        output.write(json.dumps(alert, indent=2))

