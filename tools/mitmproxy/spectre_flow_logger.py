"""Metadata-only mitmproxy addon; does not save bodies, cookies or authorization headers."""
import json, os
from datetime import datetime, timezone
from mitmproxy import http
OUTPUT=os.environ.get("SPECTRE_FLOW_LOG","reports/dynamic/network_flows.jsonl")

def response(flow: http.HTTPFlow):
    record={"timestamp_utc":datetime.now(timezone.utc).isoformat(),"flow_id":flow.id,
      "request":{"method":flow.request.method,"scheme":flow.request.scheme,"host":flow.request.host,
        "port":flow.request.port,"path":flow.request.path.split("?")[0],
        "content_length":len(flow.request.raw_content or b"")},
      "response":{"status_code":flow.response.status_code if flow.response else None,
        "content_length":len(flow.response.raw_content or b"") if flow.response else None}}
    os.makedirs(os.path.dirname(OUTPUT) or ".",exist_ok=True)
    with open(OUTPUT,"a",encoding="utf-8") as f: f.write(json.dumps(record)+"\\n")
