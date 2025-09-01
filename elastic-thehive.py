#!/usr/bin/env python3
"""
Elasticsearch to TheHive Integration Script
Monitors Elasticsearch SIEM signals and creates alerts/cases in TheHive
Handles ECS structure with focused observable extraction
"""

import time
import requests
from elasticsearch import Elasticsearch
import json
import logging
from typing import Dict, List, Any, Optional
IP = 127.0.0.1
# === CONFIGURATION ===
LAST_ID_FILE = ".last_alert_id"

# Elasticsearch Configuration
ES_HOST = "http://{IP}:9200"
ES_INDEX = ".siem-signals-default"
ES_AUTH = ("elastic", "changeme")

# TheHive Configuration
THEHIVE_BASE_URL = "http://{IP}:9000/api"
THEHIVE_ALERT_URL = f"{THEHIVE_BASE_URL}/alert"
THEHIVE_CASE_URL = f"{THEHIVE_BASE_URL}/case"
THEHIVE_API_KEY = "placeholder"

# Polling Configuration
POLL_INTERVAL = 30

# === LOGGING SETUP ===
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# === INITIALIZATION ===
es = Elasticsearch(ES_HOST, basic_auth=ES_AUTH)
headers = {
    "Authorization": f"Bearer {THEHIVE_API_KEY}",
    "Content-Type": "application/json"
}

# === CORE FUNCTIONS ===

def get_original_event_data(alert_doc: Dict[str, Any]) -> Dict[str, Any]:
    """Fetch the original event data that contains the full process information."""
    signal = alert_doc.get("signal", {})
    parents = signal.get("parents", [])
    
    if not parents:
        logger.warning("No parent events found in signal")
        return {}
    
    parent = parents[0]
    parent_id = parent.get("id")
    parent_index = parent.get("index")
    
    if not parent_id or not parent_index:
        logger.warning("Missing parent ID or index")
        return {}
    
    try:
        logger.info(f"Fetching original event {parent_id} from index {parent_index}")
        response = es.get(index=parent_index, id=parent_id)
        return response.get("_source", {})
    except Exception as e:
        logger.error(f"Error fetching original event: {str(e)}")
        return {}

def extract_process_info(alert_doc: Dict[str, Any]) -> Dict[str, Any]:
    """Extract process name, path, and hashes from ECS alert document."""
    logger.info("=== STARTING PROCESS INFO EXTRACTION ===")
    process_info = {}
    process = alert_doc.get("process", {})
    
    if isinstance(process, dict):
        name = process.get("name")
        process_info["name"] = name[0] if isinstance(name, list) and name and isinstance(name[0], str) else name if isinstance(name, str) else None
        executable = process.get("executable")
        process_info["executable"] = executable[0] if isinstance(executable, list) and executable and isinstance(executable[0], str) else executable if isinstance(executable, str) else None
        
        # Extract from process.hash
        hash_data = process.get("hash", {})
        if isinstance(hash_data, dict):
            process_info["hash_md5"] = hash_data.get("md5")
            process_info["hash_sha1"] = hash_data.get("sha1")
            process_info["hash_sha256"] = hash_data.get("sha256")
            process_info["hash_sha512"] = hash_data.get("sha512")
            process_info["hash_ssdeep"] = hash_data.get("ssdeep")
        
        pe_info = process.get("pe", {})
        if isinstance(pe_info, dict):
            process_info["pe_imphash"] = pe_info.get("imphash")
    
    # Parse winlog.event_data.Hashes string
    event_data = alert_doc.get("winlog", {}).get("event_data", {})
    hashes_string = event_data.get("Hashes")
    if hashes_string:
        logger.info(f"Found winlog.event_data.Hashes: {hashes_string}")
        for pair in hashes_string.split(","):
            if "=" in pair:
                key, value = pair.split("=", 1)
                process_info[f"hash_{key.lower()}"] = value.strip()
    
    logger.info("=== FINAL EXTRACTED PROCESS INFO ===")
    return process_info

def extract_event_info(alert_doc: Dict[str, Any]) -> Dict[str, Any]:
    """Extract event ID from ECS alert document."""
    event_info = {}
    event = alert_doc.get("event", {}) or alert_doc.get("winlog", {})
    
    if isinstance(event, dict):
        code = event.get("code") or event.get("event_id")
        event_info["code"] = str(code[0]) if isinstance(code, list) and code and isinstance(code[0], (str, int, float)) else str(code) if isinstance(code, (str, int, float)) else None
    
    return event_info

def extract_rule_info(alert_doc: Dict[str, Any]) -> Dict[str, Any]:
    """Extract detection rule information from ECS alert document."""
    rule_info = {}
    rule = (
        alert_doc.get("signal", {}).get("rule", {}) or
        alert_doc.get("kibana", {}).get("alert", {}).get("rule", {}) or
        alert_doc.get("rule", {})
    )
    
    if isinstance(rule, dict):
        name = rule.get("name")
        rule_info["name"] = name[0] if isinstance(name, list) and name and isinstance(name[0], str) else name if isinstance(name, str) else None
        description = rule.get("description")
        rule_info["description"] = description[0] if isinstance(description, list) and description and isinstance(description[0], str) else description if isinstance(description, str) else None
        rule_info["severity"] = rule.get("severity")
    
    return rule_info

def check_existing_observables(case_id: str, data: str, data_type: str) -> bool:
    """Check if an observable already exists in the case."""
    try:
        url = f"{THEHIVE_BASE_URL}/case/{case_id}/artifact/_search"
        payload = {
            "query": {
                "data": data,
                "dataType": data_type
            }
        }
        response = requests.post(url, json=payload, headers=headers)
        if response.status_code == 200:
            artifacts = response.json()
            return len(artifacts) > 0
        logger.warning(f"Failed to check existing observables: {response.text}")
        return False
    except Exception as e:
        logger.error(f"Error checking existing observables: {str(e)}")
        return False

def create_thehive_alert(alert_doc: Dict[str, Any], alert_id: str) -> Optional[str]:
    """Create an alert in TheHive from Elasticsearch alert."""
    process_info = extract_process_info(alert_doc)
    event_info = extract_event_info(alert_doc)
    rule_info = extract_rule_info(alert_doc)
    
    title = f"{rule_info.get('name', 'Security Alert')} - Alert ID {alert_id}"
    
    description_parts = [
        f"Security alert detected",
        f"Source Alert ID: {alert_id}",
        f"Timestamp: {alert_doc.get('@timestamp', 'Unknown')}"
    ]
    
    if rule_info.get("description"):
        description_parts.append(f"Rule Description: {rule_info['description']}")
    if process_info.get("name"):
        description_parts.append(f"Process: {process_info['name']}")
    if process_info.get("executable"):
        description_parts.append(f"Process Path: {process_info['executable']}")
    if event_info.get("code"):
        description_parts.append(f"Event ID: {event_info['code']}")
    
    severity = 2
    if rule_info.get("severity"):
        severity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        severity = severity_map.get(rule_info["severity"].lower(), 2)
    elif "mimikatz" in title.lower():
        severity = 4
    
    alert_payload = {
        "title": title,
        "description": "\n".join(description_parts),
        "type": "external",
        "source": "Elastic SIEM",
        "sourceRef": alert_id,
        "severity": severity,
        "tags": ["elastic-siem", "automated"],
        "artifacts": []
    }
    
    artifacts = build_alert_artifacts(process_info, event_info)
    alert_payload["artifacts"] = artifacts
    
    logger.info(f"Creating alert: {title}")
    
    try:
        response = requests.post(THEHIVE_ALERT_URL, json=alert_payload, headers=headers)
        if response.status_code == 201:
            alert_data = response.json()
            alert_thehive_id = alert_data.get('_id')
            logger.info(f"Alert created successfully! Alert ID: {alert_thehive_id}")
            return alert_thehive_id
        elif response.status_code == 400 and "already exists" in response.text:
            logger.warning("Alert already exists in TheHive")
            return None
        else:
            logger.error(f"Failed to create alert. Status: {response.status_code}")
            logger.error(f"Error: {response.text}")
            return None
    except Exception as e:
        logger.error(f"Exception creating alert: {str(e)}")
        return None

def build_alert_artifacts(process_info: Dict, event_info: Dict) -> List[Dict[str, Any]]:
    """Build artifacts list for TheHive alert."""
    artifacts = []
    
    if process_info.get("name") and isinstance(process_info["name"], str):
        artifacts.append({
            "dataType": "filename",
            "data": process_info["name"],
            "message": "Process name",
            "tags": ["process", "binary"]
        })
    
    if process_info.get("executable") and isinstance(process_info["executable"], str):
        artifacts.append({
            "dataType": "filename",
            "data": process_info["executable"],
            "message": "Process path",
            "tags": ["process", "path"]
        })
    
    hash_types = ["hash_md5", "hash_sha1", "hash_sha256", "hash_sha512", "hash_ssdeep", "pe_imphash"]
    for hash_type in hash_types:
        if process_info.get(hash_type) and isinstance(process_info[hash_type], str):
            message = "Process Import Hash (imphash)" if hash_type == "pe_imphash" else f"Process {hash_type.replace('hash_', '').upper()} hash"
            artifacts.append({
                "dataType": "hash",
                "data": process_info[hash_type],
                "message": message,
                "tags": ["process", "hash", hash_type.replace('hash_', '')]
            })
    
    if event_info.get("code") and isinstance(event_info["code"], str):
        artifacts.append({
            "dataType": "other",
            "data": event_info["code"],
            "message": "Event ID",
            "tags": ["event-code"]
        })
    
    return artifacts

def create_thehive_case(alert_doc: Dict[str, Any], alert_id: str, alert_thehive_id: Optional[str] = None) -> Optional[str]:
    """Create a case in TheHive from Elasticsearch alert."""
    process_info = extract_process_info(alert_doc)
    event_info = extract_event_info(alert_doc)
    rule_info = extract_rule_info(alert_doc)
    
    title = f"{rule_info.get('name', 'Security Incident')} - Alert ID {alert_id}"
    
    description_parts = [
        f"Security incident detected. Immediate investigation required.",
        f"Source Alert ID: {alert_id}",
        f"Timestamp: {alert_doc.get('@timestamp', 'Unknown')}"
    ]
    
    if alert_thehive_id:
        description_parts.append(f"TheHive Alert ID: {alert_thehive_id}")
    if rule_info.get("description"):
        description_parts.append(f"Rule Description: {rule_info['description']}")
    if process_info.get("name"):
        description_parts.append(f"Process Involved: {process_info['name']}")
    if process_info.get("executable"):
        description_parts.append(f"Process Path: {process_info['executable']}")
    if event_info.get("code"):
        description_parts.append(f"Event ID: {event_info['code']}")
    
    severity = 2
    if rule_info.get("severity"):
        severity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        severity = severity_map.get(rule_info["severity"].lower(), 2)
    elif "mimikatz" in title.lower():
        severity = 4
    
    case_payload = {
        "title": title,
        "description": "\n".join(description_parts),
        "severity": severity,
        "tags": ["elastic-siem", "automated", "incident"],
        "flag": False,
        "tlp": 2,
        "pap": 2
    }
    
    if "mimikatz" in rule_info.get("name", "").lower():
        try:
            template_url = f"{THEHIVE_BASE_URL}/case/template?name=Mimikatz Case"
            response = requests.get(template_url, headers=headers)
            if response.status_code == 200 and response.json():
                case_payload["template"] = "Mimikatz Case"
            else:
                logger.warning("Mimikatz Case template not found, proceeding without template")
        except Exception as e:
            logger.warning(f"Error checking template: {str(e)}, proceeding without template")
    
    logger.info(f"Creating case: {title}")
    
    try:
        response = requests.post(THEHIVE_CASE_URL, json=case_payload, headers=headers)
        if response.status_code == 201:
            case_data = response.json()
            case_id = case_data.get('_id')
            case_number = case_data.get('caseId', case_id)
            logger.info(f"Case created successfully! Case ID: {case_number}")
            add_observables_to_case(case_id, alert_doc)
            if severity >= 3:
                add_investigation_tasks(case_id, rule_info)
            return case_id
        else:
            logger.error(f"Failed to create case. Status: {response.status_code}")
            logger.error(f"Error: {response.text}")
            return None
    except Exception as e:
        logger.error(f"Exception creating case: {str(e)}")
        return None

def add_observables_to_case(case_id: str, alert_doc: Dict[str, Any]) -> None:
    """Add observables to a TheHive case."""
    process_info = extract_process_info(alert_doc)
    event_info = extract_event_info(alert_doc)
    
    observables = []
    
    if process_info.get("name") and isinstance(process_info["name"], str):
        observables.append(build_observable(
            "filename", process_info["name"], "Process name", ["process", "binary"], ioc=True
        ))
    
    if process_info.get("executable") and isinstance(process_info["executable"], str):
        observables.append(build_observable(
            "filename", process_info["executable"], "Process path", ["process", "path"], ioc=True
        ))
    
    hash_types = ["hash_md5", "hash_sha1", "hash_sha256", "hash_sha512", "hash_ssdeep", "pe_imphash"]
    for hash_type in hash_types:
        if process_info.get(hash_type) and isinstance(process_info[hash_type], str):
            message = "Process Import Hash (imphash)" if hash_type == "pe_imphash" else f"Process {hash_type.replace('hash_', '').upper()} hash"
            observables.append(build_observable(
                "hash", process_info[hash_type], message, 
                ["process", "hash", hash_type.replace('hash_', '')], ioc=True
            ))
    
    if event_info.get("code") and isinstance(event_info["code"], str):
        observables.append(build_observable(
            "other", event_info["code"], "Event ID", ["event-code"]
        ))
    
    logger.info(f"Adding {len(observables)} observables to case {case_id}")
    
    for i, observable in enumerate(observables):
        if not isinstance(observable, dict):
            logger.error(f"[Index {i}] Skipping invalid observable (not a dict): {observable}")
            continue
        try:
            data = observable.get("data")
            data_type = observable.get("dataType", "unknown")
            if not isinstance(data, str):
                logger.warning(f"Skipping invalid observable {data_type}: data is not a string ({data})")
                continue
            if check_existing_observables(case_id, data, data_type):
                logger.info(f"Observable {data_type} - {data} already exists, skipping")
                continue
            url = f"{THEHIVE_BASE_URL}/case/{case_id}/artifact"
            response = requests.post(url, json=observable, headers=headers)
            if response.status_code == 201:
                response_data = response.json()
                observable_id = response_data.get('_id') if isinstance(response_data, dict) else response_data[0].get('_id') if response_data else None
                logger.info(f"Added observable: {data_type} - {data}")
            else:
                logger.warning(f"Failed to add observable {data_type} - {data}: {response.text}")
        except Exception as e:
            logger.error(f"Exception adding observable {data_type} - {data if 'data' in locals() else 'unknown'}: {str(e)}")

def build_observable(data_type: str, data: str, message: str, tags: List[str], 
                    ioc: bool = False, sighted: bool = True) -> Dict[str, Any]:
    """Build a single observable dictionary for TheHive."""
    if not isinstance(data, str):
        logger.warning(f"Invalid data for observable {data_type}: {data} is not a string")
        return {}
    return {
        "dataType": data_type,
        "data": data,
        "message": message,
        "tags": tags,
        "ioc": ioc,
        "sighted": sighted
    }

def add_investigation_tasks(case_id: str, rule_info: Dict[str, str]) -> None:
    """Add investigation tasks to a high-severity case."""
    tasks = [
        {
            "title": "Initial Analysis",
            "description": "Perform initial analysis of the security incident",
            "status": "Waiting",
            "flag": False
        },
        {
            "title": "Evidence Collection",
            "description": "Collect and preserve relevant evidence from affected systems",
            "status": "Waiting",
            "flag": False
        }
    ]
    
    rule_name = rule_info.get("name", "").lower()
    if "mimikatz" in rule_name:
        tasks.extend([
            {
                "title": "Mitigate Mimikatz",
                "description": "Mimikatz detected. Mitigate immediately and investigate access",
                "status": "Waiting",
                "flag": True
            },
            {
                "title": "Credential Reset",
                "description": "Reset credentials for affected accounts and review privileges",
                "status": "Waiting",
                "flag": True
            }
        ])
    
    for task in tasks:
        try:
            url = f"{THEHIVE_BASE_URL}/case/{case_id}/task"
            response = requests.post(url, json=task, headers=headers)
            if response.status_code == 201:
                logger.info(f"Added task: {task['title']}")
            else:
                logger.warning(f"Failed to add task '{task['title']}': {response.text}")
        except Exception as e:
            logger.error(f"Exception adding task: {str(e)}")

def process_alert(alert_doc: Dict[str, Any], alert_id: str) -> tuple[Optional[str], Optional[str]]:
    """Process a single alert: create alert and case in TheHive."""
    logger.info(f"Processing alert ID: {alert_id}")
    
    original_event = get_original_event_data(alert_doc)
    if original_event:
        logger.info("Using original event data for hash extraction")
        combined_doc = {**alert_doc, **original_event}
    else:
        logger.warning("Could not fetch original event, using signal data only")
        combined_doc = alert_doc
    
    alert_thehive_id = create_thehive_alert(combined_doc, alert_id)
    case_id = create_thehive_case(combined_doc, alert_id, alert_thehive_id)
    
    if alert_thehive_id and case_id:
        logger.info(f"Successfully created alert {alert_thehive_id} and case {case_id}")
    elif case_id:
        logger.info(f"Successfully created case {case_id}")
    else:
        logger.error("Failed to create alert and case")
    
    return alert_thehive_id, case_id

def poll_alerts() -> None:
    """Main polling loop to monitor Elasticsearch for new alerts."""
    last_alert_id = None
    try:
        with open(LAST_ID_FILE, "r") as f:
            last_alert_id = f.read().strip()
        logger.info(f"Loaded last alert ID: {last_alert_id}")
    except FileNotFoundError:
        logger.info("No previous alert ID found, starting fresh")
    
    logger.info("Starting alert polling loop...")
    
    while True:
        try:
            res = es.search(
                index=ES_INDEX,
                size=1,
                sort=[{"@timestamp": "desc"}],
                query={"match_all": {}}
            )
            hits = res.get("hits", {}).get("hits", [])
            if hits:
                alert = hits[0]
                alert_id = alert["_id"]
                alert_doc = alert["_source"]
                if alert_id != last_alert_id:
                    logger.info(f"New alert detected: {alert_id}")
                    alert_thehive_id, case_id = process_alert(alert_doc, alert_id)
                    last_alert_id = alert_id
                    with open(LAST_ID_FILE, "w") as f:
                        f.write(alert_id)
                    logger.info(f"Updated last alert ID to: {alert_id}")
                else:
                    logger.debug("No new alerts")
            else:
                logger.warning("No documents found in index")
        except Exception as e:
            logger.error(f"Error polling alerts: {str(e)}")
        logger.debug(f"Sleeping for {POLL_INTERVAL} seconds...")
        time.sleep(POLL_INTERVAL)

# === MAIN EXECUTION ===
if __name__ == "__main__":
    logger.info("Starting Elasticsearch to TheHive Integration")
    logger.info(f"Elasticsearch: {ES_HOST}")
    logger.info(f"TheHive: {THEHIVE_BASE_URL}")
    logger.info(f"Poll interval: {POLL_INTERVAL} seconds")
    
    try:
        if es.ping():
            logger.info("Elasticsearch connection successful")
        else:
            logger.error("Failed to connect to Elasticsearch")
            exit(1)
        poll_alerts()
    except KeyboardInterrupt:
        logger.info("Shutting down gracefully...")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        exit(1)
