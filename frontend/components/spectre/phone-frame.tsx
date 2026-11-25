"use client"

import {
  AlertTriangle,
  FileText,
  Fingerprint,
  Globe,
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
  packageName?: string
  socialData?: any
  riskPermissions?: string[]
}

function normalizeStringList(val: any): string[] {
  if (!val) return []
  if (Array.isArray(val)) {
    return val
      .map((item) => {
        if (typeof item === "string") return item.trim()
        if (item && typeof item === "object") {
          return String(item.label ?? item.field ?? item.keyword ?? item.indicator ?? item.value ?? item.text ?? "").trim()
        }
        return ""
      })
      .filter(Boolean)
  }
  return []
}

export function PhoneFrame({
  activeStep,
  stepId = 1,
  brandName,
  packageName,
  socialData,
  riskPermissions = [],
}: PhoneFrameProps) {
  const rawDevice = activeStep?.device || {}
  const social = socialData || {}

  const effectiveBrand =
    brandName ||
    social?.app_name ||
    social?.brand_name ||
    activeStep?.brand_name ||
    activeStep?.brand ||
    rawDevice?.brand ||
    packageName ||
    "Target APK"

  const effectivePkg =
    packageName ||
    social?.package_name ||
    activeStep?.package_name ||
    rawDevice?.package_name ||
    ""

  const socialScore = Number(
    social?.social_engineering_score ??
      social?.social_score ??
      activeStep?.social_score ??
      0,
  )

  const lureArchetype = String(
    rawDevice?.lure_tag ??
      activeStep?.lure_type ??
      activeStep?.archetype ??
      social?.archetype ??
      "",
  ).trim()

  // Grab actual extracted lure strings / keywords / URLs / form fields from backend output
  const extractedIndicators = Array.from(
    new Set([
      ...normalizeStringList(rawDevice?.indicators),
      ...normalizeStringList(activeStep?.indicators),
      ...normalizeStringList(activeStep?.matched_keywords),
      ...normalizeStringList(social?.matched_keywords),
      ...normalizeStringList(social?.lure_indicators),
      ...normalizeStringList(social?.suspicious_strings),
    ]),
  )

  const extractedUrls = Array.from(
    new Set([
      ...normalizeStringList(rawDevice?.urls),
      ...normalizeStringList(activeStep?.urls),
      ...normalizeStringList(social?.phishing_urls),
      ...normalizeStringList(social?.lure_urls),
    ]),
  )

  const extractedInputs = Array.from(
    new Set([
      ...normalizeStringList(rawDevice?.inputs),
      ...normalizeStringList(activeStep?.inputs),
      ...normalizeStringList(activeStep?.fields),
      ...normalizeStringList(social?.harvest_fields),
    ]),
  )

  const rawBody =
    rawDevice.body ??
    activeStep?.description ??
    activeStep?.body ??
    social?.summary ??
    social?.reason ??
    ""

  const rawHeader =
    rawDevice.header ??
    activeStep?.ui_header ??
    activeStep?.header ??
    effectiveBrand

  const rawSub =
    rawDevice.sub ??
    activeStep?.ui_subtext ??
    activeStep?.subtitle ??
    activeStep?.sub ??
    (lureArchetype || (effectivePkg ? `pkg: ${effectivePkg}` : ""))

  const rawButton =
    rawDevice.button ??
    activeStep?.button ??
    activeStep?.cta ??
    "Inspect Step"

  const rawExtra =
    rawDevice.extra_info ??
    activeStep?.extra_info ??
    (extractedUrls[0] ? `Endpoint: ${extractedUrls[0]}` : "")

  const inferredScreenType =
    rawDevice.screen_type ||
    activeStep?.screen_type ||
    (extractedInputs.length > 0
      ? "FORM"
      : /otp|sms|code|pin/i.test(`${rawHeader} ${rawBody} ${lureArchetype}`)
        ? "OTP"
        : /alert|warning|urgent|kyc|suspend|update|permission|accessibility|overlay/i.test(
              `${rawHeader} ${rawBody} ${lureArchetype}`,
            )
          ? "ALERT_MODAL"
          : stepId === 2
            ? "ALERT_MODAL"
            : stepId === 3
              ? "FORM"
              : stepId === 4
                ? "OTP"
                : "SPLASH")

  const device = {
    ...rawDevice,
    header: rawHeader,
    sub: rawSub,
    body: rawBody,
    inputs: extractedInputs,
    indicators: extractedIndicators,
    urls: extractedUrls,
    button: rawButton,
    icon: rawDevice.icon || activeStep?.icon,
    screen_type: inferredScreenType,
    extra_info: rawExtra,
  }

  const perms =
    Array.isArray(rawDevice.permissions) && rawDevice.permissions.length > 0
      ? rawDevice.permissions
      : Array.isArray(activeStep?.permissions) && activeStep.permissions.length > 0
        ? activeStep.permissions
        : riskPermissions

  const isElevated = socialScore >= 50 || Boolean(lureArchetype)

  return (
    <div className="relative mx-auto flex w-[285px] sm:w-[305px] flex-col items-center">
      <div
        className={`relative flex h-[540px] w-full flex-col overflow-hidden rounded-[42px] border-[6px] bg-slate-950 p-4 shadow-[0_0_35px_-8px_rgba(6,182,212,0.18)] ring-1 ${
          isElevated
            ? "border-rose-900/80 ring-rose-500/30"
            : "border-slate-800 ring-slate-800/80"
        }`}
      >
        {/* Notch */}
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

        {/* Dynamic M4 / Archetype Header Bar */}
        {(lureArchetype || socialScore > 0) && (
          <div className="relative z-10 mt-2 flex items-center justify-between rounded-lg border border-amber-500/30 bg-amber-950/30 px-2.5 py-1 font-mono text-[9px] text-amber-300">
            <span className="truncate">{lureArchetype || "SOCIAL_SIGNAL"}</span>
            {socialScore > 0 && (
              <span className="ml-2 shrink-0 font-bold">M4:{Math.round(socialScore)}</span>
            )}
          </div>
        )}

        {/* Active Screen */}
        <div className="relative flex flex-1 flex-col justify-center overflow-y-auto pt-2">
          {device.screen_type === "ALERT_MODAL" ? (
            <ScreenAlert device={device} brand={effectiveBrand} />
          ) : device.screen_type === "FORM" ? (
            <ScreenForm device={device} brand={effectiveBrand} />
          ) : device.screen_type === "OTP" ? (
            <ScreenOtp device={device} brand={effectiveBrand} />
          ) : (
            <ScreenSplash device={device} brand={effectiveBrand} />
          )}
        </div>

        {/* Actual Extracted APK Permission Badges */}
        {Array.isArray(perms) && perms.length > 0 && (
          <div className="relative z-10 mt-2 flex flex-wrap gap-1 border-t border-slate-800/80 pt-2">
            {perms.slice(0, 3).map((perm: string) => (
              <span
                key={perm}
                className="inline-flex items-center gap-1 rounded bg-rose-500/15 px-1.5 py-0.5 font-mono text-[8px] text-rose-300"
              >
                <AlertTriangle className="size-2.5" />
                {String(perm).split(".").pop()}
              </span>
            ))}
          </div>
        )}
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

function ExtractedEvidenceBox({ device }: { device: any }) {
  const indicators: string[] = device.indicators || []
  const urls: string[] = device.urls || []

  if (indicators.length === 0 && urls.length === 0) return null

  return (
    <div className="mt-3 w-full space-y-1.5 text-left">
      {indicators.slice(0, 3).map((tok, i) => (
        <div
          key={`ind-${i}`}
          className="truncate rounded-md border border-amber-500/25 bg-amber-950/25 px-2 py-1 font-mono text-[9px] text-amber-200"
          title={tok}
        >
          APK Lure: {tok}
        </div>
      ))}
      {urls.slice(0, 2).map((u, i) => (
        <div
          key={`url-${i}`}
          className="flex items-center gap-1 truncate rounded-md border border-slate-800 bg-slate-900/90 px-2 py-1 font-mono text-[9px] text-cyan-300"
          title={u}
        >
          <Globe className="size-2.5 shrink-0 text-cyan-400" />
          <span className="truncate">{u}</span>
        </div>
      ))}
    </div>
  )
}

function ScreenSplash({ device, brand }: { device: any; brand: string }) {
  return (
    <div className="flex h-full flex-col items-center justify-center text-center">
      <div className="mb-4 flex size-14 items-center justify-center rounded-2xl border border-cyan-500/40 bg-cyan-950/40 text-cyan-400 shadow-[0_0_24px_-4px_rgba(6,182,212,0.35)]">
        {renderIcon(device.icon || "shield", "size-6 stroke-[2.2]")}
      </div>

      <h4 className="text-base font-bold tracking-tight text-slate-100">{device.header}</h4>
      {device.sub && <p className="mt-1 break-all font-mono text-[10px] text-slate-400">{device.sub}</p>}
      {device.body && (
        <p className="mt-2.5 max-w-[235px] text-[11px] leading-relaxed text-slate-300">
          {device.body}
        </p>
      )}

      <ExtractedEvidenceBox device={device} />

      {device.button && (
        <div className="mt-4 w-full rounded-xl bg-cyan-400 py-2 text-xs font-bold text-slate-950 shadow-[0_0_16px_rgba(6,182,212,0.4)]">
          {device.button}
        </div>
      )}
    </div>
  )
}

function ScreenAlert({ device, brand }: { device: any; brand: string }) {
  return (
    <div className="my-auto flex flex-col items-center justify-center">
      <div className="relative w-full rounded-2xl border border-rose-500/30 bg-gradient-to-b from-rose-950/30 via-slate-950/80 to-slate-950 p-4 text-center shadow-[0_0_30px_-5px_rgba(244,63,94,0.3)]">
        <div className="mx-auto mb-2.5 flex size-11 items-center justify-center rounded-full border border-rose-500/40 bg-rose-950/60 text-rose-500 shadow-[0_0_16px_rgba(244,63,94,0.4)]">
          {renderIcon(device.icon || "alert", "size-5")}
        </div>

        <h4 className="text-sm font-bold leading-tight text-rose-400">{device.header}</h4>
        {device.body && (
          <p className="mt-2 text-[11px] leading-relaxed text-slate-300">{device.body}</p>
        )}

        <ExtractedEvidenceBox device={device} />

        {device.button && (
          <div className="mt-4 w-full rounded-xl bg-gradient-to-r from-rose-600 via-rose-500 to-rose-600 py-2 text-xs font-bold text-white shadow-[0_0_18px_rgba(244,63,94,0.45)]">
            {device.button}
          </div>
        )}

        {device.extra_info && (
          <div className="mt-2.5 flex items-center justify-center gap-1.5 truncate font-mono text-[9px] text-slate-400">
            <Timer className="size-3 shrink-0 text-slate-400" />
            <span className="truncate">{device.extra_info}</span>
          </div>
        )}
      </div>
    </div>
  )
}

function ScreenForm({ device, brand }: { device: any; brand: string }) {
  const inputs: string[] = Array.isArray(device.inputs) ? device.inputs : []

  return (
    <div className="flex h-full flex-col justify-between py-1">
      <div>
        <div className="flex items-center gap-2">
          {renderIcon(device.icon || "lock", "size-4 shrink-0 text-cyan-400")}
          <h4 className="truncate text-sm font-bold tracking-tight text-slate-100">
            {device.header}
          </h4>
        </div>
        {device.body && (
          <p className="mt-1.5 text-[11px] leading-relaxed text-slate-400">{device.body}</p>
        )}

        {inputs.length > 0 && (
          <div className="mt-3 space-y-2">
            {inputs.slice(0, 3).map((label: string, idx: number) => (
              <div key={idx}>
                <label className="block truncate font-mono text-[9px] uppercase tracking-wider text-slate-400">
                  {label}
                </label>
                <div className="mt-1 flex h-7.5 w-full items-center rounded-xl border border-slate-700/80 bg-slate-900/90 px-3 font-mono text-[10px] text-slate-400">
                  {label}
                </div>
              </div>
            ))}
          </div>
        )}
        {inputs.length === 0 && (
          <div className="mt-3 rounded-xl border border-dashed border-slate-800 bg-slate-900/50 p-3 text-center font-mono text-[10px] text-slate-500">
            No static credential input fields extracted from APK
          </div>
        )}

        <ExtractedEvidenceBox device={device} />

        {device.button && (
          <div className="mt-4 w-full rounded-xl bg-cyan-400 py-2 text-center text-xs font-bold text-slate-950 shadow-[0_0_16px_rgba(6,182,212,0.4)]">
            {device.button}
          </div>
        )}
      </div>

      <div className="flex items-center justify-center gap-1.5 font-mono text-[9px] text-slate-500">
        <Fingerprint className="size-3 text-slate-500" />
        <span>Extracted from {brand}</span>
      </div>
    </div>
  )
}

function ScreenOtp({ device, brand }: { device: any; brand: string }) {
  return (
    <div className="flex h-full flex-col justify-between py-1">
      <div>
        {device.extra_info && (
          <div className="mb-3 flex items-center gap-2 rounded-lg border border-amber-500/40 bg-amber-950/40 p-2 text-[10px] text-amber-300">
            <Radio className="size-3.5 shrink-0 animate-pulse text-amber-400" />
            <span className="truncate leading-tight">{device.extra_info}</span>
          </div>
        )}

        <div className="flex items-center gap-2">
          {renderIcon(device.icon || "lock", "size-4 shrink-0 text-cyan-400")}
          <h4 className="truncate text-sm font-bold tracking-tight text-slate-100">
            {device.header}
          </h4>
        </div>
        {device.body && (
          <p className="mt-1.5 text-[11px] leading-relaxed text-slate-400">{device.body}</p>
        )}

        <ExtractedEvidenceBox device={device} />

        {device.button && (
          <div className="mt-4 w-full rounded-xl bg-cyan-400 py-2 text-center text-xs font-bold text-slate-950 shadow-[0_0_16px_rgba(6,182,212,0.4)]">
            {device.button}
          </div>
        )}
      </div>

      <div className="flex items-center justify-center gap-1.5 font-mono text-[9px] text-slate-500">
        <span>{brand} · M4 Lure Telemetry</span>
      </div>
    </div>
  )
}