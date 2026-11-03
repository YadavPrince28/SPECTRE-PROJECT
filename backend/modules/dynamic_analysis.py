
from __future__ import annotations
import hashlib, json, os, re, shutil, socket, subprocess, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
try:
    from androguard.core.apk import APK
except Exception:
    APK = None

MODULE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = MODULE_DIR.parents[1]
CAPTURE_ROOT = PROJECT_ROOT / "data" / "captures" / "module3"
AVD_NAME = os.environ.get("SPECTRE_AVD_NAME", "Spectre_Sandbox_API30")

class DynamicAnalysisError(RuntimeError):
    pass

def _now(): return datetime.now(timezone.utc).isoformat()
def _safe_id(value):
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value or ""))[:64].strip("._-")
    return value or uuid.uuid4().hex[:12]

def _sdk_root():
    return Path(os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME") or
                (Path(os.environ.get("LOCALAPPDATA", str(Path.home())))/"Android"/"Sdk"))
def _resolve_adb():
    found = shutil.which("adb")
    candidate = _sdk_root()/"platform-tools"/("adb.exe" if os.name == "nt" else "adb")
    if found: return found
    if candidate.exists(): return str(candidate)
    raise DynamicAnalysisError("ADB not found; install Android SDK Platform Tools or add adb to PATH.")
def _resolve_emulator():
    path = _sdk_root()/"emulator"/("emulator.exe" if os.name == "nt" else "emulator")
    if not path.exists(): raise DynamicAnalysisError(f"Android Emulator executable not found: {path}")
    return path
def _resolve_mitmdump():
    override = os.environ.get("SPECTRE_MITMDUMP")
    if override and Path(override).exists(): return override
    root = PROJECT_ROOT.parent/"spectre-proxy-env"
    for path in (root/"Scripts"/"mitmdump.exe", root/"bin"/"mitmdump"):
        if path.exists(): return str(path)
    return shutil.which("mitmdump")
def _run(cmd, timeout=20, check=False):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise DynamicAnalysisError(f"Command timed out after {timeout}s: {Path(cmd[0]).name}") from e
    except OSError as e:
        raise DynamicAnalysisError(f"Could not start {Path(cmd[0]).name}: {e}") from e
    if check and p.returncode:
        raise DynamicAnalysisError(f"{Path(cmd[0]).name} exited {p.returncode}: {(p.stderr or p.stdout)[-1000:]}")
    return p
def _adb(adb, serial, *args, timeout=20, check=False):
    return _run([adb, "-s", serial, *map(str, args)], timeout, check)
def _online_emulators(adb):
    out = _run([adb, "devices", "-l"], 15, True).stdout
    return [p[0] for line in out.splitlines()[1:] if len(p:=line.split())>=2 and p[0].startswith("emulator-") and p[1]=="device"]
def _wait_boot(adb, serial, timeout=180):
    end = time.monotonic()+timeout
    while time.monotonic()<end:
        try:
            if _adb(adb, serial, "shell", "getprop", "sys.boot_completed", timeout=8).stdout.strip()=="1": return
        except DynamicAnalysisError: pass
        time.sleep(3)
    raise DynamicAnalysisError(f"Emulator {serial} did not complete boot within {timeout}s.")
def _ensure_emulator(adb):
    wanted = os.environ.get("SPECTRE_ADB_SERIAL", "").strip()
    devices = _online_emulators(adb)
    launched = False
    if wanted:
        if not wanted.startswith("emulator-") or wanted not in devices:
            raise DynamicAnalysisError(f"SPECTRE_ADB_SERIAL must name an online emulator; online: {devices}")
        serial = wanted
    elif len(devices)==1: serial = devices[0]
    elif len(devices)>1: raise DynamicAnalysisError(f"Multiple emulators online: {devices}; set SPECTRE_ADB_SERIAL.")
    else:
        exe = _resolve_emulator()
        avds = _run([str(exe), "-list-avds"], 20, True).stdout.splitlines()
        if AVD_NAME not in avds: raise DynamicAnalysisError(f"AVD '{AVD_NAME}' not found. Available AVDs: {avds}")
        subprocess.Popen([str(exe), "-avd", AVD_NAME, "-no-boot-anim"], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name=="nt" else 0)
        launched = True; end = time.monotonic()+60; serial = ""
        while time.monotonic()<end:
            devices = _online_emulators(adb)
            if len(devices)==1: serial=devices[0]; break
            if len(devices)>1: raise DynamicAnalysisError(f"Multiple emulators appeared: {devices}")
            time.sleep(2)
        if not serial: raise DynamicAnalysisError("AVD was started but did not become visible to ADB within 60s.")
    _wait_boot(adb, serial)
    qemu = _adb(adb, serial, "shell", "getprop", "ro.kernel.qemu", timeout=10).stdout.strip()
    if qemu not in {"", "1"}: raise DynamicAnalysisError(f"Refusing non-emulator device (ro.kernel.qemu={qemu!r}).")
    release = _adb(adb, serial, "shell", "getprop", "ro.build.version.release", timeout=10).stdout.strip()
    sdk = _adb(adb, serial, "shell", "getprop", "ro.build.version.sdk", timeout=10).stdout.strip()
    return serial, {"device_serial":serial, "is_emulator":True, "android_release":release, "android_sdk":sdk,
                    "avd_name":AVD_NAME, "emulator_launched_by_module":launched}
def _sha256(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024), b""): h.update(chunk)
    return h.hexdigest()
def _port():
    with socket.socket() as s: s.bind(("127.0.0.1", 0)); return s.getsockname()[1]
def _start_proxy(run_dir, port, jsonl, proxy_log):
    exe = _resolve_mitmdump(); addon = MODULE_DIR/"mitm_jsonl_addon.py"
    if not exe: return None, "mitmdump executable not found; network capture disabled."
    if not addon.exists(): return None, f"JSONL addon not found: {addon}"
    env=os.environ.copy(); env["SPECTRE_MITM_EVENTS_FILE"]=str(jsonl)
    conf=run_dir/"mitmproxy_conf"; conf.mkdir(parents=True, exist_ok=True)
    cmd=[exe,"--quiet","--listen-host","127.0.0.1","--listen-port",str(port),"--set",f"confdir={conf}","-s",str(addon)]
    try:
        fh=proxy_log.open("w",encoding="utf-8",errors="replace")
        proc=subprocess.Popen(cmd,cwd=str(PROJECT_ROOT),env=env,stdin=subprocess.DEVNULL,stdout=fh,stderr=subprocess.STDOUT,
                              creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0) if os.name=="nt" else 0)
        proc._spectre_log_handle=fh
    except OSError as e: return None, f"Could not launch mitmdump: {e}"
    end=time.monotonic()+12
    while time.monotonic()<end:
        if proc.poll() is not None: break
        try:
            with socket.create_connection(("127.0.0.1",port),timeout=.4): return proc,None
        except OSError: time.sleep(.25)
    _stop_process(proc)
    tail=proxy_log.read_text(encoding="utf-8",errors="replace")[-700:] if proxy_log.exists() else ""
    return None, f"mitmproxy failed to listen. {tail.strip()}"
def _stop_process(proc):
    if not proc: return
    if proc.poll() is None:
        try: proc.terminate(); proc.wait(timeout=8)
        except Exception:
            try: proc.kill(); proc.wait(timeout=3)
            except Exception: pass
    fh=getattr(proc,"_spectre_log_handle",None)
    if fh:
        try: fh.close()
        except Exception: pass
def _proxy_setting(adb, serial):
    val=_adb(adb,serial,"shell","settings","get","global","http_proxy",timeout=10).stdout.strip()
    return "" if val.lower() in {"null","none"} else val
def _set_proxy(adb, serial, val):
    if val: _adb(adb,serial,"shell","settings","put","global","http_proxy",val,timeout=10)
    else: _adb(adb,serial,"shell","settings","delete","global","http_proxy",timeout=10)
def _appops(adb, serial, pkg):
    p=_adb(adb,serial,"shell","cmd","appops","get",pkg,timeout=20)
    return (p.stdout or p.stderr or "").strip()
def _runtime_grants(adb, serial, pkg):
    text=_adb(adb,serial,"shell","dumpsys","package",pkg,timeout=20).stdout
    m=re.search(r"runtime permissions:\s*(.*?)(?:\n\s*install permissions:|\Z)",text,re.I|re.S)
    return sorted({line.strip().split(":",1)[0].strip() for line in (m.group(1) if m else "").splitlines()
                   if "granted=true" in line.lower() and line.strip().startswith("android.permission.")})
def _jsonl(path):
    events=[]; warnings=[]
    if not path.exists(): return events,warnings
    for no,line in enumerate(path.read_text(encoding="utf-8",errors="replace").splitlines(),1):
        if not line.strip(): continue
        try:
            x=json.loads(line)
            if isinstance(x,dict): events.append(x)
        except json.JSONDecodeError: warnings.append(f"Could not parse network event line {no}.")
    return events,warnings
def _network_summary(events):
    reqs={}; errors=[]
    for e in events:
        fid=str(e.get("flow_id", "")); kind=e.get("event")
        if kind=="http_request":
            reqs[fid or f"r{len(reqs)}"]={k:e.get(k) for k in ("timestamp","method","scheme","host","path","query_parameter_names","content_type","body_size_bytes","sensitive_field_names_observed")}
            reqs[fid or f"r{len(reqs)-1}"]["response_status"]=None
        elif kind=="http_response" and fid in reqs: reqs[fid]["response_status"]=e.get("status_code")
        elif kind=="http_error":
            errors.append({k:e.get(k) for k in ("timestamp","host","error_type","message")})
            if fid in reqs: reqs[fid]["tls_or_transport_error"]=e.get("message")
    rows=list(reqs.values())[:300]
    return {"request_count":len(reqs),"hosts":sorted({r.get("host") for r in rows if r.get("host")}),"requests":rows,
            "transport_errors":errors[:100],"sensitive_field_request_count":sum(bool(r.get("sensitive_field_names_observed")) for r in rows)}
def _log_signals(path, pkg):
    lines=[]; crashes=[]
    if path.exists():
        with path.open("r",encoding="utf-8",errors="replace") as f:
            for line in f:
                line=line.rstrip()
                if pkg.lower() in line.lower():
                    if len(lines)<100: lines.append(line[:400])
                    if re.search(r"FATAL EXCEPTION|Process:\s*"+re.escape(pkg)+r"|has died|crash",line,re.I) and len(crashes)<25: crashes.append(line[:400])
    return {"package_associated_line_count":len(lines),"crash_detected":bool(crashes),"crash_evidence":crashes,"package_log_evidence":lines[:50]}
def _findings(network, logs, appops_delta):
    found=[]; sens=[r for r in network.get("requests",[]) if r.get("sensitive_field_names_observed")]
    clear=[r for r in network.get("requests",[]) if r.get("scheme")=="http" and r.get("host") not in {"localhost","127.0.0.1","10.0.2.2"}]
    if sens: found.append({"id":"OUTBOUND_REQUEST_SENSITIVE_FIELD_NAMES","severity":"medium","points":25,
        "title":"Outbound request contains sensitive-looking field names",
        "description":"Request keys resemble authentication or account fields. Values were not retained; this is suspicious evidence, not proof real secrets were sent.",
        "evidence":[{k:r.get(k) for k in ("host","path","method","sensitive_field_names_observed","body_size_bytes")} for r in sens[:10]]})
    if clear: found.append({"id":"OUTBOUND_CLEARTEXT_HTTP","severity":"low","points":10,
        "title":"Cleartext HTTP request observed","description":"An outbound request used HTTP, which may expose content in transit but is not proof of malicious intent.",
        "evidence":[{k:r.get(k) for k in ("host","path","method")} for r in clear[:10]]})
    if logs.get("crash_detected"): found.append({"id":"APP_CRASH_OBSERVED","severity":"informational","points":0,
        "title":"Package-associated crash evidence observed","description":"A crash affects execution coverage and is not a malware signal by itself.","evidence":logs.get("crash_evidence",[])[:10]})
    if appops_delta: found.append({"id":"APPOPS_STATE_CHANGED","severity":"informational","points":0,
        "title":"AppOps snapshot changed after execution","description":"Snapshot differences are supplied for analyst review; they do not prove successful sensitive-operation use.","evidence":appops_delta[:25]})
    return found,min(100,sum(int(f.get("points",0)) for f in found))

def analyze_dynamic(apk_path: str, job_id: str = "", static_result: dict[str, Any] | None = None) -> dict[str, Any]:
    """Analyze one APK on an Android emulator and return JSON-serializable evidence.

    ``static_result`` is reserved for the integration stage; leaving it optional keeps
    the current pipeline invocation compatible.
    """
    started=time.monotonic(); run_id=_safe_id(job_id)
    result={"module":"dynamic_analysis","schema_version":"1.0","job_id":run_id,"started_at":_now(),
        "status":"failed","package_name":None,"apk_sha256":None,"dynamic_risk_score":0,
        "risk_score_type":"heuristic evidence score (0-100), not a probability","findings":[],"evidence":{},"errors":[],
        "coverage":{"logcat_capture":False,"http_proxy_capture":False,"https_decryption_verified":False,
            "direct_socket_traffic_guaranteed_captured":False,"limitations":[
                "The HTTP proxy is not a network-isolation boundary; apps may bypass it or use direct sockets.",
                "HTTPS inspection depends on trust configuration and app behavior; this MVP does not bypass TLS pinning.",
                "No behavior observed in a run does not establish that an APK is safe.",
                "AppOps and granted-permission snapshots are observations, not proof a permission was actively used."]}}
    adb=serial=pkg=None; proxy_proc=logcat_proc=logcat_handle=None; previous_proxy=None; proxy_changed=False; installed=False
    run_dir=logcat_path=network_path=proxy_log=meta_path=None
    try:
        apk_path_obj=Path(apk_path).expanduser().resolve()
        if not apk_path_obj.is_file(): raise DynamicAnalysisError(f"APK file does not exist: {apk_path_obj}")
        if apk_path_obj.suffix.lower() != ".apk": raise DynamicAnalysisError("Input file must have an .apk extension.")
        if APK is None: raise DynamicAnalysisError("Androguard import failed in the main spectre-env.")
        apk=APK(str(apk_path_obj)); pkg=(apk.get_package() or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+",pkg):
            raise DynamicAnalysisError(f"Could not resolve a valid package name from APK: {pkg!r}")
        declared=sorted(set(apk.get_permissions() or []))
        result["package_name"]=pkg; result["apk_sha256"]=_sha256(apk_path_obj)
        result["evidence"]["apk"]={"path":str(apk_path_obj),"size_bytes":apk_path_obj.stat().st_size,"declared_permissions":declared}
        adb=_resolve_adb(); serial,env_info=_ensure_emulator(adb); result["environment"]=env_info
        run_dir=CAPTURE_ROOT/run_id; run_dir.mkdir(parents=True,exist_ok=True)
        logcat_path=run_dir/"logcat.txt"; network_path=run_dir/"network_events.jsonl"; proxy_log=run_dir/"mitmproxy.log"; meta_path=run_dir/"run_metadata.json"
        for p in (logcat_path,network_path,proxy_log):
            try: p.unlink()
            except FileNotFoundError: pass
        result["evidence"]["artifact_directory"]=str(run_dir)
        result["evidence"]["files"]={"logcat":str(logcat_path),"network_events_jsonl":str(network_path),"proxy_log":str(proxy_log),"metadata":str(meta_path)}

        # Start proxy as a separate process in spectre-proxy-env, then set emulator proxy.
        proxy_exe=_resolve_mitmdump(); chosen_port=_port() if proxy_exe else None; proxy_warning=None
        if proxy_exe and chosen_port is not None:
            proxy_proc,proxy_warning=_start_proxy(run_dir,chosen_port,network_path,proxy_log)
        else: proxy_warning="mitmdump executable not found; continuing with runtime collection only."
        if proxy_proc and chosen_port is not None:
            previous_proxy=_proxy_setting(adb,serial)
            _set_proxy(adb,serial,f"10.0.2.2:{chosen_port}"); proxy_changed=True
            result["coverage"]["http_proxy_capture"]=True
            result["evidence"]["network_capture"]={"emulator_proxy":"10.0.2.2","port":chosen_port,"proxy_executable":proxy_exe}
        if proxy_warning: result["errors"].append(proxy_warning)

        _adb(adb,serial,"logcat","-c",timeout=10)
        logcat_handle=logcat_path.open("w",encoding="utf-8",errors="replace")
        logcat_proc=subprocess.Popen([adb,"-s",serial,"logcat","-v","threadtime"],stdout=logcat_handle,
            stderr=subprocess.DEVNULL,stdin=subprocess.DEVNULL,
            creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0) if os.name=="nt" else 0)
        result["coverage"]["logcat_capture"]=True

        # This module should be run only on the disposable SPECTRE AVD.
        # Uninstall a previous user-installed instance to avoid stale state.
        _adb(adb,serial,"uninstall",pkg,timeout=30)
        installed_result=_adb(adb,serial,"install","-t",str(apk_path_obj),timeout=120)
        if installed_result.returncode != 0 or "success" not in installed_result.stdout.lower():
            raise DynamicAnalysisError(f"APK installation failed: {(installed_result.stderr or installed_result.stdout).strip()[-1000:]}")
        installed=True; time.sleep(2)
        appops_before=_appops(adb,serial,pkg); grants_before=_runtime_grants(adb,serial,pkg)
        monkey_events=max(20,min(int(os.environ.get("SPECTRE_MONKEY_EVENTS","120")),500))
        throttle=max(100,min(int(os.environ.get("SPECTRE_MONKEY_THROTTLE_MS","400")),1500))
        monkey=_adb(adb,serial,"shell","monkey","-p",pkg,"-c","android.intent.category.LAUNCHER",
            "--throttle",str(throttle),"--ignore-crashes","--ignore-timeouts",str(monkey_events),
            timeout=max(150,int(monkey_events*throttle/1000)+90))
        time.sleep(5)
        appops_after=_appops(adb,serial,pkg); grants_after=_runtime_grants(adb,serial,pkg)

        if logcat_proc and logcat_proc.poll() is None:
            logcat_proc.terminate()
            try: logcat_proc.wait(timeout=8)
            except subprocess.TimeoutExpired: logcat_proc.kill(); logcat_proc.wait(timeout=3)
        if logcat_handle: logcat_handle.flush(); logcat_handle.close(); logcat_handle=None
        # Stop proxy before reading JSONL so its final events are flushed.
        _stop_process(proxy_proc); proxy_proc=None

        logs=_log_signals(logcat_path,pkg); raw_network,warnings=_jsonl(network_path); net=_network_summary(raw_network)
        appops_delta=sorted({line.strip() for line in appops_after.splitlines() if line.strip()}-
                            {line.strip() for line in appops_before.splitlines() if line.strip()})[:100]
        findings,risk=_findings(net,logs,appops_delta)
        result["execution"]={"install_success":True,"monkey_return_code":monkey.returncode,
            "monkey_output_tail":(monkey.stdout or "").strip()[-1000:],"monkey_error_tail":(monkey.stderr or "").strip()[-1000:],
            "events_requested":monkey_events,"throttle_ms":throttle,"runtime_granted_permissions_before":grants_before,
            "runtime_granted_permissions_after":grants_after,"runtime_granted_permission_delta":sorted(set(grants_after)-set(grants_before)),
            "appops_before":appops_before.splitlines()[:100],"appops_after":appops_after.splitlines()[:100],"appops_changed_lines":appops_delta}
        result["evidence"]["logcat"]=logs; result["evidence"]["network"]={**net,"event_records":len(raw_network)}
        result["findings"]=findings; result["dynamic_risk_score"]=risk
        result["coverage"]["https_decryption_verified"]=any(r.get("scheme")=="https" and r.get("response_status") is not None for r in net.get("requests",[]))
        if warnings: result["errors"].extend(warnings[:10])
        result["status"]="complete" if result["coverage"]["http_proxy_capture"] else "partial"
        if monkey.returncode != 0:
            result["status"]="partial"; result["errors"].append("Android Monkey returned a non-zero exit code; behavior coverage may be incomplete.")
        if not result["coverage"]["https_decryption_verified"]:
            result["coverage"]["limitations"].append("No completed HTTPS flow was verified in this run; HTTPS content visibility is unconfirmed.")
        if static_result:
            result["integration_note"]="static_result argument received; endpoint-level correlation will be added after initial runtime tests."
        result["completed_at"]=_now(); result["duration_seconds"]=round(time.monotonic()-started,2)
        meta_path.write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding="utf-8")
        return result
    except Exception as exc:
        result["status"]="failed"; result["errors"].append(f"{type(exc).__name__}: {exc}")
        result["completed_at"]=_now(); result["duration_seconds"]=round(time.monotonic()-started,2)
        if meta_path:
            try: meta_path.write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding="utf-8")
            except OSError: pass
        return result
    finally:
        if logcat_proc and logcat_proc.poll() is None:
            try: logcat_proc.terminate(); logcat_proc.wait(timeout=5)
            except Exception:
                try: logcat_proc.kill()
                except Exception: pass
        if logcat_handle:
            try: logcat_handle.close()
            except Exception: pass
        _stop_process(proxy_proc)
        if adb and serial and proxy_changed:
            try: _set_proxy(adb,serial,previous_proxy)
            except Exception: pass
        if adb and serial and pkg and installed:
            try: _adb(adb,serial,"uninstall",pkg,timeout=30)
            except Exception: pass
