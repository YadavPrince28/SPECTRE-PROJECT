
from __future__ import annotations
import json, os, re, threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit
from mitmproxy import http

OUTPUT = Path(os.environ.get("SPECTRE_MITM_EVENTS_FILE", "network_events.jsonl"))
LOCK = threading.Lock()
SENSITIVE_RE = re.compile(r"(?i)(?:^|[\s\"'&,;{])(otp|one[_-]?time[_-]?password|password|passwd|passcode|pin|token|access[_-]?token|refresh[_-]?token|authorization|credential|account[_-]?number|card[_-]?number|cvv|secret)[\s\"']*(?::|=)")
SENSITIVE_KEY_RE = re.compile(r"(?i)^(otp|one[_-]?time[_-]?password|password|passwd|passcode|pin|token|access[_-]?token|refresh[_-]?token|authorization|credential|account[_-]?number|card[_-]?number|cvv|secret)$")
LONG_NUMBER = re.compile(r"\d{7,}")

def _now(): return datetime.now(timezone.utc).isoformat()
def _safe_path(path):
    path=LONG_NUMBER.sub("<redacted-number>",path or "/")
    return "/".join("<redacted-segment>" if len(x)>64 else x for x in path.split("/"))[:500]
def _url_parts(url):
    try:
        p=urlsplit(url)
        return p.hostname, (p.scheme or "").lower() or None, _safe_path(p.path), sorted({k[:80] for k,_ in parse_qsl(p.query,keep_blank_values=True)})[:50]
    except Exception: return None,None,None,[]
def _sensitive_keys(raw, query_keys):
    names={k.lower() for k in query_keys if SENSITIVE_KEY_RE.match(k)}
    if raw:
        text=raw[:1024*1024].decode("utf-8",errors="ignore")
        names.update(m.group(1).lower() for m in SENSITIVE_RE.finditer(text))
    return sorted(names)[:30]
def _write(row):
    OUTPUT.parent.mkdir(parents=True,exist_ok=True)
    row=dict(row); row.setdefault("timestamp",_now())
    with LOCK:
        with OUTPUT.open("a",encoding="utf-8") as f:
            f.write(json.dumps(row,ensure_ascii=False,separators=(",",":"))+"\n"); f.flush()

class SpectreJsonlAddon:
    def request(self, flow: http.HTTPFlow):
        host,scheme,path,query_keys=_url_parts(flow.request.pretty_url)
        raw=flow.request.raw_content
        _write({"event":"http_request","flow_id":flow.id,"method":flow.request.method,"host":host,"scheme":scheme,
            "path":path,"query_parameter_names":query_keys,"content_type":(flow.request.headers.get("content-type","") or "")[:120],
            "body_size_bytes":len(raw or b""),"sensitive_field_names_observed":_sensitive_keys(raw,query_keys)})
    def response(self, flow: http.HTTPFlow):
        host,scheme,path,_=_url_parts(flow.request.pretty_url)
        _write({"event":"http_response","flow_id":flow.id,"host":host,"scheme":scheme,"path":path,
            "status_code":flow.response.status_code if flow.response else None})
    def error(self, flow: http.HTTPFlow):
        host,scheme,path,_=_url_parts(flow.request.pretty_url if flow.request else "")
        err=flow.error
        _write({"event":"http_error","flow_id":flow.id,"host":host,"scheme":scheme,"path":path,
            "error_type":type(err).__name__ if err else "UnknownError","message":str(err.msg if err else "transport error")[:300]})

addons=[SpectreJsonlAddon()]
