"""Offline tests for SPECTRE Module 3 evidence processing."""
import importlib.util, json, tempfile, unittest
from pathlib import Path
MODULE_PATH=Path(__file__).parents[1]/"backend"/"modules"/"dynamic_analysis.py"
spec=importlib.util.spec_from_file_location("spectre_dynamic_analysis",MODULE_PATH)
module=importlib.util.module_from_spec(spec); assert spec and spec.loader; spec.loader.exec_module(module)

class TestModule3Helpers(unittest.TestCase):
    def test_jsonl_reader_handles_bad_lines(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"events.jsonl"; p.write_text('{"event":"http_request","host":"example.test"}\nBAD\n',encoding="utf-8")
            events,warnings=module._jsonl(p)
            self.assertEqual(len(events),1); self.assertEqual(events[0]["host"],"example.test"); self.assertEqual(len(warnings),1)
    def test_unknown_post_is_not_exfiltration_by_itself(self):
        network={"requests":[{"host":"unknown.example","scheme":"https","method":"POST","path":"/collect","sensitive_field_names_observed":[]}]}
        findings,score=module._findings(network,{"crash_detected":False},[])
        self.assertEqual(score,0); self.assertFalse(any("EXFILTRATION" in x["id"] for x in findings))
    def test_sensitive_field_names_create_caveated_finding(self):
        network={"requests":[{"host":"example.test","scheme":"https","method":"POST","path":"/submit","body_size_bytes":18,"sensitive_field_names_observed":["password"]}]}
        findings,score=module._findings(network,{"crash_detected":False},[])
        self.assertEqual(score,25); self.assertEqual(findings[0]["id"],"OUTBOUND_REQUEST_SENSITIVE_FIELD_NAMES")
    def test_cleartext_http_is_low_severity(self):
        network={"requests":[{"host":"example.test","scheme":"http","method":"GET","path":"/status","sensitive_field_names_observed":[]}]}
        findings,score=module._findings(network,{"crash_detected":False},[])
        self.assertEqual(score,10); self.assertEqual(findings[0]["id"],"OUTBOUND_CLEARTEXT_HTTP")
    def test_job_id_is_sanitized(self): self.assertEqual(module._safe_id("job / 1"),"job_1")

if __name__=="__main__": unittest.main(verbosity=2)
