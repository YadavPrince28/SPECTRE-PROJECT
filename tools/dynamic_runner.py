import argparse, hashlib, json, os, re, shutil, subprocess, time
from datetime import datetime, timezone
from pathlib import Path

def now():
    return datetime.now(timezone.utc).isoformat()

def cmd(args, timeout=30):
    try:
        p=subprocess.run(args, capture_output=True, text=True, timeout=timeout, errors="replace")
        return {"returncode":p.returncode,"stdout":p.stdout,"stderr":p.stderr}
    except subprocess.TimeoutExpired:
        return {"returncode":-1,"stdout":"","stderr":f"timeout after {timeout}s"}

def adb(serial,*args,timeout=30):
    return cmd(["adb","-s",serial,*args],timeout)

def get_aapt():
    if shutil.which("aapt"): return shutil.which("aapt")
    sdk=os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if sdk:
        hits=sorted(Path(sdk,"build-tools").glob("*/aapt.exe"),reverse=True)
        if hits: return str(hits[0])
    return None

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--apk",required=True); ap.add_argument("--serial",default="emulator-5554")
    ap.add_argument("--seconds",type=int,default=60); ap.add_argument("--output",default="reports/dynamic")
    args=ap.parse_args()
    apk=Path(args.apk).resolve()
    if not apk.is_file(): raise SystemExit(f"APK not found: {apk}")
    out=Path(args.output).resolve(); out.mkdir(parents=True,exist_ok=True)
    stamp=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stem=apk.stem+"_"+stamp; report_path=out/(stem+".json"); log_path=out/(stem+"_logcat.txt")
    report={"schema_version":"spectre-dynamic-1.0","started_utc":now(),
      "apk":{"path":str(apk),"sha256":hashlib.sha256(apk.read_bytes()).hexdigest()},
      "device":{"serial":args.serial},"execution_status":"incomplete","crash_detected":False,
      "runtime_indicators":[],"network":{"capture_status":"not_configured","capture_method":None,
      "flows_file":None,"note":"ADB diagnostics are not packet capture; optional mitmproxy records only proxied flows."},
      "coverage":{"duration_seconds":args.seconds,"launch_attempted":False},
      "risk":{"dynamic_score":None,"confidence":"insufficient_evidence"},"artifacts":{},"errors":[]}
    state=adb(args.serial,"get-state")
    if state["returncode"] or state["stdout"].strip()!="device":
        report["execution_status"]="device_unavailable"; report["errors"].append(state["stderr"] or state["stdout"])
        report["finished_utc"]=now(); report_path.write_text(json.dumps(report,indent=2),encoding="utf-8")
        print(report_path); return
    for key,prop in [("android_sdk","ro.build.version.sdk"),("abi","ro.product.cpu.abi"),("model","ro.product.model")]:
        report["device"][key]=adb(args.serial,"shell","getprop",prop)["stdout"].strip()
    aapt=get_aapt()
    if not aapt:
        raise SystemExit("aapt not found. Set ANDROID_HOME or add Android SDK build-tools to PATH.")
    b=cmd([aapt,"dump","badging",str(apk)],45)
    m=re.search(r"package: name='([^']+)'",b["stdout"])
    if not m:
        report["execution_status"]="package_detection_failed"; report["errors"].append(b["stderr"] or "aapt could not read package")
        report["finished_utc"]=now(); report_path.write_text(json.dumps(report,indent=2),encoding="utf-8"); return
    package=m.group(1); report["package"]=package
    adb(args.serial,"logcat","-c")
    ins=adb(args.serial,"install","-r",str(apk),timeout=180)
    report["install"]={k:ins[k] for k in ("returncode","stdout","stderr")}
    if ins["returncode"] or "Success" not in ins["stdout"]:
        report["execution_status"]="install_failed"; report["errors"].append("APK installation failed")
        report["finished_utc"]=now(); report_path.write_text(json.dumps(report,indent=2),encoding="utf-8"); print(report_path); return
    with log_path.open("w",encoding="utf-8",errors="replace") as log:
        proc=subprocess.Popen(["adb","-s",args.serial,"logcat","-v","threadtime"],stdout=log,stderr=subprocess.STDOUT,text=True)
        try:
            launch=adb(args.serial,"shell","monkey","-p",package,"-c","android.intent.category.LAUNCHER","1",timeout=30)
            report["launch"]={k:launch[k] for k in ("returncode","stdout","stderr")}
            report["coverage"]["launch_attempted"]=True
            time.sleep(max(5,min(args.seconds,600)))
        finally:
            proc.terminate()
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: proc.kill()
    log=log_path.read_text(encoding="utf-8",errors="replace")
    report["artifacts"]["logcat"]=str(log_path)
    patterns=[("fatal_exception",r"FATAL EXCEPTION"),("fatal_signal",r"Fatal signal \\d+"),
      ("anr",r"ANR in "),("process_died",r"Process .* has died"),
      ("unsatisfied_link",r"UnsatisfiedLinkError"),("security_exception",r"SecurityException")]
    for name,pat in patterns:
        lines=[x for x in log.splitlines() if re.search(pat,x,re.I)]
        if lines: report["runtime_indicators"].append({"type":name,"count":len(lines),"samples":lines[:8]})
    report["crash_detected"]=any(x["type"] in ("fatal_exception","fatal_signal","unsatisfied_link") for x in report["runtime_indicators"])
    for label,parts in [("connectivity",["shell","dumpsys","connectivity"]),("netstats",["shell","dumpsys","netstats","detail"]),
                        ("package_dump",["shell","dumpsys","package",package]),("processes",["shell","ps","-A"])]:
        r=adb(args.serial,*parts,timeout=40); f=out/(stem+"_"+label+".txt")
        f.write_text(r["stdout"] or r["stderr"],encoding="utf-8",errors="replace"); report["artifacts"][label]=str(f)
    flows=out/"network_flows.jsonl"
    if flows.exists() and flows.stat().st_size:
        report["network"].update({"capture_status":"flow_log_present","capture_method":"mitmproxy metadata; proxied traffic only",
          "flows_file":str(flows),"flow_count":sum(1 for line in flows.open(encoding="utf-8",errors="replace") if line.strip())})
    report["execution_status"]="crashed" if report["crash_detected"] else ("execution_attempted" if launch["returncode"]==0 else "launch_unconfirmed")
    report["risk"]["confidence"]="insufficient_evidence" if report["crash_detected"] else "low"
    report["finished_utc"]=now(); report_path.write_text(json.dumps(report,indent=2),encoding="utf-8")
    print("Status:",report["execution_status"]); print("Crash:",report["crash_detected"]); print("JSON:",report_path)

if __name__=="__main__": main()
