"use client"

import {
  FileText,
  Fingerprint,
  Lock,
  Radio,
  Shield,
  ShieldAlert,
  Smartphone,
  Sparkles,
  Timer,
  Truck,
  Zap,
} from "lucide-react"

interface PhoneFrameProps {
  activeStep?: any
  stepId?: number
  brandName?: string
}

export function PhoneFrame({
  activeStep,
  stepId = 1,
  brandName,
}: PhoneFrameProps) {
  // Normalize data: support both nested `device` object and flat `activeStep` properties
  const rawDevice = activeStep?.device || {}
  
  const effectiveBrand =
    brandName ||
    activeStep?.brand_name ||
    activeStep?.brand ||
    rawDevice?.brand ||
    "Application"

  const device = {
    ...rawDevice,
    header:
      rawDevice.header ||
      activeStep?.ui_header ||
      activeStep?.header ||
      `${effectiveBrand} Service`,
    sub:
      rawDevice.sub ||
      activeStep?.ui_subtext ||
      activeStep?.subtitle ||
      activeStep?.sub ||
      `Initializing ${effectiveBrand}`,
    body:
      rawDevice.body ||
      activeStep?.description ||
      activeStep?.body ||
      `Initializing runtime environment for ${effectiveBrand}...`,
    inputs: rawDevice.inputs || activeStep?.inputs,
    button: rawDevice.button || activeStep?.button || "Continue",
    icon: rawDevice.icon || activeStep?.icon,
    screen_type:
      rawDevice.screen_type ||
      activeStep?.screen_type ||
      (stepId === 2 ? "ALERT_MODAL" : stepId === 3 ? "FORM" : stepId === 4 ? "OTP" : "SPLASH"),
    extra_info: rawDevice.extra_info || activeStep?.extra_info,
  }

  const screenType = device.screen_type

  return (
    <div className="relative mx-auto flex w-[285px] sm:w-[305px] flex-col items-center">
      {/* Outer Phone Shell */}
      <div className="relative flex h-[540px] w-full flex-col overflow-hidden rounded-[42px] border-[6px] border-slate-800 bg-slate-950 p-4 shadow-[0_0_35px_-8px_rgba(6,182,212,0.18)] ring-1 ring-slate-800/80">
        
        {/* Dynamic Island / Notch */}
        <div className="absolute left-1/2 top-2.5 z-20 h-4 w-28 -translate-x-1/2 rounded-full bg-slate-900" />

        {/* Status Bar */}
        <div className="relative z-10 flex items-center justify-between px-3 pt-1 text-[10px] font-medium text-slate-400">
          <span>9:41</span>
          <div className="flex items-center gap-1.5 text-[9px]">
            <span>5G</span>
            <span>·</span>
            <span>84%</span>
          </div>
        </div>

        {/* Screen Content Container */}
        <div className="relative flex flex-1 flex-col justify-center overflow-hidden pt-3">
          {screenType === "ALERT_MODAL" ? (
            <ScreenAlert device={device} brand={effectiveBrand} />
          ) : screenType === "FORM" ? (
            <ScreenForm device={device} brand={effectiveBrand} />
          ) : screenType === "OTP" ? (
            <ScreenOtp device={device} brand={effectiveBrand} />
          ) : (
            <ScreenSplash device={device} brand={effectiveBrand} />
          )}
        </div>
      </div>
    </div>
  )
}

function renderIcon(iconName?: string, className?: string) {
  switch (iconName) {
    case "zap":
      return <Zap className={className} />
    case "sparkles":
      return <Sparkles className={className} />
    case "truck":
      return <Truck className={className} />
    case "file-text":
      return <FileText className={className} />
    case "shield":
      return <Shield className={className} />
    case "smartphone":
      return <Smartphone className={className} />
    case "alert":
      return <ShieldAlert className={className} />
    default:
      return <Lock className={className} />
  }
}

/**
 * Screen 1: Splash / Feature Lure
 */
function ScreenSplash({ device, brand }: { device: any; brand: string }) {
  const header = device.header || `${brand} Service`
  const sub = device.sub || `Welcome to ${brand}`
  const body = device.body || `Initializing secure runtime session for ${brand}...`
  const button = device.button || "Continue"
  const iconName = device.icon || "shield"

  return (
    <div className="flex h-full flex-col items-center justify-center text-center">
      {/* Glowing Icon Box */}
      <div className="mb-6 flex size-18 items-center justify-center rounded-2xl border border-cyan-500/40 bg-cyan-950/40 text-cyan-400 shadow-[0_0_24px_-4px_rgba(6,182,212,0.35)]">
        {renderIcon(iconName, "size-8 stroke-[2.2]")}
      </div>

      <h4 className="text-lg font-bold tracking-tight text-slate-100">
        {header}
      </h4>
      <p className="mt-1 text-xs font-semibold text-slate-300">
        {sub}
      </p>

      <p className="mt-3.5 max-w-[220px] text-[11px] leading-relaxed text-slate-400">
        {body}
      </p>

      {device.inputs && device.inputs.length > 0 ? (
        <div className="mt-4 w-full space-y-2">
          {device.inputs.map((inp: string, i: number) => (
            <div key={i} className="rounded-lg border border-slate-800 bg-slate-900/80 px-2.5 py-1.5 text-left font-mono text-[10px] text-slate-400">
              {inp}
            </div>
          ))}
        </div>
      ) : (
        <div className="mt-8 flex h-1.5 w-28 overflow-hidden rounded-full bg-slate-800">
          <div className="w-2/3 rounded-full bg-cyan-400 shadow-[0_0_8px_rgba(6,182,212,0.8)]" />
        </div>
      )}

      {device.button && (
        <button
          type="button"
          className="mt-6 w-full rounded-xl bg-cyan-400 py-2 text-xs font-bold text-slate-950 shadow-[0_0_16px_rgba(6,182,212,0.4)]"
        >
          {button}
        </button>
      )}
    </div>
  )
}

/**
 * Screen 2: Alert Modal / Urgency Engineering
 */
function ScreenAlert({ device, brand }: { device: any; brand: string }) {
  const header = device.header || "Permission Required"
  const body = device.body || `${brand} requires elevated runtime access to operate normally.`
  const button = device.button || "Grant Access"
  const extra = device.extra_info || "Action Required"
  const iconName = device.icon || "alert"

  return (
    <div className="my-auto flex flex-col items-center justify-center">
      <div className="relative w-full rounded-2xl border border-rose-500/30 bg-gradient-to-b from-rose-950/30 via-slate-950/80 to-slate-950 p-5 text-center shadow-[0_0_30px_-5px_rgba(244,63,94,0.3)]">
        <div className="mx-auto mb-3 flex size-13 items-center justify-center rounded-full border border-rose-500/40 bg-rose-950/60 shadow-[0_0_16px_rgba(244,63,94,0.4)] text-rose-500">
          {renderIcon(iconName, "size-6")}
        </div>

        <h4 className="text-[15px] font-bold leading-tight text-rose-400">
          {header}
        </h4>
        <p className="mt-2.5 text-[11px] leading-relaxed text-slate-300">
          {body}
        </p>

        <button
          type="button"
          className="mt-5 w-full rounded-xl bg-gradient-to-r from-rose-600 via-rose-500 to-rose-600 py-2.5 text-xs font-bold text-white shadow-[0_0_18px_rgba(244,63,94,0.45)] transition hover:brightness-110"
        >
          {button}
        </button>

        <div className="mt-3 flex items-center justify-center gap-1.5 font-mono text-[10px] text-slate-400">
          <Timer className="size-3 text-slate-400" />
          <span>{extra}</span>
        </div>
      </div>
    </div>
  )
}

/**
 * Screen 3: Form / Credential Harvest
 */
function ScreenForm({ device, brand }: { device: any; brand: string }) {
  const header = device.header || "Device Verification"
  const body = device.body || `Provide device configuration to continue using ${brand}.`
  const button = device.button || "Submit"
  const inputs = device.inputs && device.inputs.length > 0 ? device.inputs : ["ACCOUNT IDENTIFIER", "PIN / PASSCODE"]

  return (
    <div className="flex h-full flex-col justify-between pt-1 pb-1">
      <div>
        <div className="flex items-center gap-2">
          {renderIcon(device.icon || "lock", "size-4 text-cyan-400")}
          <h4 className="text-sm font-bold tracking-tight text-slate-100">
            {header}
          </h4>
        </div>
        <p className="mt-2 text-[11px] leading-relaxed text-slate-400">
          {body}
        </p>

        <div className="mt-4 space-y-3">
          {inputs.map((label: string, idx: number) => (
            <div key={idx}>
              <label className="block font-mono text-[9px] uppercase tracking-wider text-slate-400">
                {label}
              </label>
              <div className="mt-1 flex h-8.5 w-full items-center rounded-xl border border-slate-700/80 bg-slate-900/90 px-3 font-mono text-xs tracking-widest text-slate-300">
                ••••••••
              </div>
            </div>
          ))}
        </div>

        <button
          type="button"
          className="mt-5 w-full rounded-xl bg-cyan-400 py-2.5 text-xs font-bold text-slate-950 shadow-[0_0_16px_rgba(6,182,212,0.4)] transition hover:bg-cyan-300"
        >
          {button}
        </button>
      </div>

      <div className="flex items-center justify-center gap-1.5 font-mono text-[10px] text-slate-500">
        <Fingerprint className="size-3.5 text-slate-500" />
        <span>Sandboxed Local Execution</span>
      </div>
    </div>
  )
}

/**
 * Screen 4: OTP Capture / Surveillance
 */
function ScreenOtp({ device, brand }: { device: any; brand: string }) {
  const header = device.header || "Authorization Code"
  const body = device.body || `Enter the confirmation code sent for ${brand}.`
  const extra = device.extra_info || "Background listener active"
  const button = device.button || "Authorize"

  return (
    <div className="flex h-full flex-col justify-between pt-1 pb-1">
      <div>
        {/* Warning Badge */}
        <div className="mb-3.5 flex items-center gap-2 rounded-lg border border-amber-500/40 bg-amber-950/40 p-2 text-[10px] text-amber-300 shadow-[0_0_12px_rgba(245,158,11,0.2)]">
          <Radio className="size-3.5 shrink-0 animate-pulse text-amber-400" />
          <span className="leading-tight">{extra}</span>
        </div>

        <div className="flex items-center gap-2">
          {renderIcon(device.icon || "lock", "size-4 text-cyan-400")}
          <h4 className="text-sm font-bold tracking-tight text-slate-100">
            {header}
          </h4>
        </div>
        <p className="mt-1.5 text-[11px] leading-relaxed text-slate-400">
          {body}
        </p>

        {/* PIN Grid */}
        <div className="mt-5 flex justify-between gap-1">
          {["•", "•", "•", "•", "•", "•"].map((digit, idx) => (
            <div
              key={idx}
              className="flex size-9 items-center justify-center rounded-lg border border-cyan-500/40 bg-slate-900 font-mono text-xs font-bold text-cyan-300 shadow-[0_0_8px_rgba(6,182,212,0.2)]"
            >
              {digit}
            </div>
          ))}
        </div>

        <button
          type="button"
          className="mt-6 w-full rounded-xl bg-cyan-400 py-2.5 text-xs font-bold text-slate-950 shadow-[0_0_16px_rgba(6,182,212,0.4)] transition hover:bg-cyan-300"
        >
          {button}
        </button>
      </div>

      <div className="flex items-center justify-center gap-1.5 font-mono text-[9px] text-slate-500">
        <span>Channel encrypted via TLS</span>
      </div>
    </div>
  )
}