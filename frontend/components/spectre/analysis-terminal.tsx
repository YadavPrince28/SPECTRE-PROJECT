"use client"

import { useEffect, useRef, useState } from "react"
import {
  Activity,
  AlertTriangle,
  CircleAlert,
  GitBranch,
  Network,
  Terminal,
} from "lucide-react"
import { cn } from "@/lib/utils"
import {
  MITM_LOG,
  RUNTIME_DELTA,
  STORYBOARD,
} from "@/lib/spectre-data"
import { getRiskBand, RiskGauge } from "./risk-gauge"
import { PhoneFrame } from "./phone-frame"

const BANK_PACKAGE_TOKENS = [
  "com.boi.ua.android",
  "com.sbi",
  "com.axis",
  "com.icici",
  "com.hdfc",
  "com.canara",
  "com.kotak",
  "bankofbaroda",
]

function detectOfficialBank(result: any, packageName: string, authenticityStatus: string): boolean {
  const pkgLower = String(packageName ?? "").toLowerCase()
  const authUpper = String(authenticityStatus ?? "").toUpperCase()
  const socialArchetype = String(result?.social?.archetype ?? "").toUpperCase()
  const socialAuthStatus = String(result?.social?.authenticity?.status ?? "").toUpperCase()

  return (
    authUpper === "AUTHENTIC_OFFICIAL_BANK" ||
    authUpper === "VERIFIED" ||
    socialArchetype === "BENIGN_OFFICIAL_BANK" ||
    socialAuthStatus === "AUTHENTIC_OFFICIAL_BANK" ||
    BANK_PACKAGE_TOKENS.some((tok) => pkgLower.includes(tok))
  )
}

function getTierStyles(tier: "LOW" | "MODERATE" | "HIGH" | "CRITICAL") {
  switch (tier) {
    case "LOW":
      return {
        cardClass: "border-emerald-500/40 shadow-[0_0_16px_-4px_rgba(16,185,129,0.35)]",
        scoreClass: "text-emerald-400",
        pillClass: "bg-emerald-500/15 text-emerald-400",
      }
    case "MODERATE":
      return {
        cardClass: "border-amber-500/40 shadow-[0_0_16px_-4px_rgba(245,158,11,0.35)]",
        scoreClass: "text-amber-400",
        pillClass: "bg-amber-500/15 text-amber-400",
      }
    case "HIGH":
      return {
        cardClass: "border-orange-500/40 shadow-[0_0_16px_-4px_rgba(249,115,22,0.35)]",
        scoreClass: "text-orange-400",
        pillClass: "bg-orange-500/15 text-orange-400",
      }
    default:
      return {
        cardClass: "animate-breathe-crimson border-rose-500/40",
        scoreClass: "text-rose-400",
        pillClass: "bg-rose-500/15 text-rose-400",
      }
  }
}

export function AnalysisTerminal({ result }: { result: any }) {
  const packageName =
    result?.static?.package_name ??
    result?.static?.package ??
    "Unknown APK"

  const authenticity = result?.static?.authenticity ?? {}
  const authenticityStatus = authenticity?.status ?? "UNVERIFIED"
  const authenticityBank = authenticity?.bank_name ?? ""
  const isOfficialBank = detectOfficialBank(result, packageName, authenticityStatus)

  const rawScore = Number(result?.final_score?.score ?? 94)
  const rawVerdict = result?.final_score?.verdict ?? "CRITICAL"
  const band = getRiskBand(rawScore, isOfficialBank, rawVerdict)
  const riskScore = band.score
  const verdict = band.label

  return (
    <div className="flex flex-col gap-6">
      <Header
        packageName={packageName}
        authenticityStatus={authenticityStatus}
        authenticityBank={authenticityBank}
        isOfficialBank={isOfficialBank}
      />
      <QuickMetrics
        result={result}
        riskScore={riskScore}
        verdict={verdict}
        isOfficialBank={isOfficialBank}
      />

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <LeftColumn
          result={result}
          riskScore={riskScore}
          verdict={verdict}
          isOfficialBank={isOfficialBank}
        />
        <RightColumn result={result} />
      </div>

      {/* Dynamic Telemetry & Behavior Delta connected to backend output */}
      <MitmConsole dynamic={result?.dynamic} />
      <RuntimeDelta dynamic={result?.dynamic} />
    </div>
  )
}

function Header({
  packageName,
  authenticityStatus,
  authenticityBank,
  isOfficialBank,
}: {
  packageName: string
  authenticityStatus: string
  authenticityBank: string
  isOfficialBank: boolean
}) {
  const badgeStyle =
    isOfficialBank || authenticityStatus === "VERIFIED" || authenticityStatus === "AUTHENTIC_OFFICIAL_BANK"
      ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
      : authenticityStatus === "CERTIFICATE_MISMATCH"
        ? "border-red-500/30 bg-red-500/10 text-red-400"
        : "border-slate-700 bg-slate-800/50 text-slate-400"

  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-center gap-2">
        <span className="rounded-md border border-rose-500/30 bg-rose-500/10 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-rose-400">
          View 02
        </span>
        <h2 className="text-xl font-semibold text-slate-100">Advanced Analysis Terminal</h2>
      </div>
      <p className="text-sm text-slate-500">
        Multi-dimensional structural fingerprinting and live runtime behavioral telemetry for{" "}
        <span className="font-mono text-slate-400">{packageName}</span>
        <span
          className={cn(
            "ml-2 inline-flex items-center rounded-md border px-2 py-0.5 font-mono text-[10px] font-bold",
            badgeStyle,
          )}
        >
          AUTHENTICITY: {isOfficialBank && authenticityStatus === "UNVERIFIED" ? "OFFICIAL_BANK" : authenticityStatus}
        </span>
        {authenticityBank && (
          <span className="ml-2 font-mono text-[10px] text-slate-500">
            · {authenticityBank}
          </span>
        )}.
      </p>
    </div>
  )
}

function QuickMetrics({
  result,
  riskScore,
  verdict,
  isOfficialBank,
}: {
  result: any
  riskScore: number
  verdict: string
  isOfficialBank: boolean
}) {
  const behavioral = result?.behavioral ?? {}
  const closestFamily = behavioral?.closest_family ?? "No behavioral match"
  const behavioralScore = Number(behavioral?.behavioral_score ?? 0)
  const classScore = Number(behavioral?.class_idf_score ?? 0)
  const packageScore = Number(behavioral?.package_markov_score ?? 0)
  const margin = Number(behavioral?.top1_margin_percent ?? 0)

  const band = getRiskBand(riskScore, isOfficialBank, verdict)
  const tierStyles = getTierStyles(band.tier)

  // Dual-Layer Network Threat Resolution
  const exfiltrationEvents = isOfficialBank ? [] : (result?.dynamic?.exfiltration_events ?? [])
  const activeStreams = isOfficialBank
    ? 0
    : (result?.dynamic?.active_streams?.length ?? exfiltrationEvents.length)
  const latentHosts = isOfficialBank
    ? []
    : (
        result?.dynamic?.latent_c2_targets ??
        result?.dynamic?.network_delta?.dormant_static_hosts ??
        result?.static?.c2_urls ??
        []
      )
  const latentCount = latentHosts.length

  const networkScore = isOfficialBank
    ? 0
    : (
        result?.final_score?.component_scores?.network_exfiltration ??
        (exfiltrationEvents.length > 0 ? 100 : latentCount > 0 ? 25 : 0)
      )

  const isNetworkRisk = !isOfficialBank && (exfiltrationEvents.length > 0 || networkScore > 0 || latentCount > 0)

  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
      {/* FINAL RISK */}
      <div
        className={cn(
          "glass-card relative overflow-hidden rounded-2xl border p-5 transition-colors",
          tierStyles.cardClass,
        )}
      >
        <p className="font-mono text-[10px] uppercase tracking-wider text-slate-400">
          Composite Risk Vector
        </p>
        <div className="mt-2 flex items-end gap-2">
          <span className={cn("font-mono text-4xl font-bold", tierStyles.scoreClass)}>
            {Math.round(riskScore)}
          </span>
          <span className="mb-1 font-mono text-sm text-slate-500">/100</span>
        </div>
        <span
          className={cn(
            "mt-3 inline-flex items-center gap-1 rounded-md px-2 py-1 font-mono text-[10px] font-bold tracking-wider",
            tierStyles.pillClass,
          )}
        >
          <CircleAlert className="size-3" />
          {verdict}
        </span>
      </div>

      {/* BEHAVIORAL DNA */}
      <div className="glass-card rounded-2xl border border-slate-800 p-5">
        <p className="font-mono text-[10px] uppercase tracking-wider text-slate-400">
          Behavioral Graph Match
        </p>
        <div className="mt-2 flex items-center gap-3">
          <GitBranch className="size-7 text-cyan-400" />
          <span className="text-lg font-semibold text-slate-100">{closestFamily}</span>
        </div>
        <p className="mt-3 font-mono text-xs text-cyan-400">
          Behavioral Similarity: {behavioralScore.toFixed(2)}%
        </p>
        <p className="mt-1 font-mono text-[10px] text-slate-500">
          Class-IDF: {(classScore * 100).toFixed(2)}% · Package Markov: {(packageScore * 100).toFixed(2)}%
        </p>
        <p className="mt-1 font-mono text-[10px] text-slate-500">
          Top-1 margin: {margin.toFixed(2)}%
        </p>
      </div>

      {/* DUAL-LAYER NETWORK EXFILTRATION STATUS */}
      <div
        className={cn(
          "glass-card rounded-2xl p-5 border transition-colors",
          isNetworkRisk
            ? exfiltrationEvents.length > 0
              ? "border-rose-500/40"
              : "border-amber-500/40"
            : "border-slate-800",
        )}
      >
        <p className="font-mono text-[10px] uppercase tracking-wider text-slate-400">
          Network Exfiltration Status
        </p>

        {isNetworkRisk ? (
          <>
            <div className="mt-2 flex items-center gap-2">
              <AlertTriangle
                className={cn(
                  "size-6",
                  exfiltrationEvents.length > 0 ? "text-rose-400" : "text-amber-400",
                )}
              />
              <span
                className={cn(
                  "text-base font-bold tracking-tight",
                  exfiltrationEvents.length > 0 ? "text-rose-400" : "text-amber-400",
                )}
              >
                {exfiltrationEvents.length > 0
                  ? "EXFILTRATION DETECTED"
                  : "DORMANT ENDPOINTS DISCOVERED"}
              </span>
            </div>

            <p className="mt-3 font-mono text-xs text-slate-300">
              {exfiltrationEvents.length > 0
                ? `${exfiltrationEvents.length} active runtime stream(s) intercepted`
                : `${latentCount} uncontacted external host(s) identified in binary`}
            </p>

            <p className="mt-1 font-mono text-[10px] text-slate-500">
              {activeStreams} active stream(s) · {latentCount} latent target(s)
            </p>
          </>
        ) : (
          <>
            <div className="mt-2 flex items-center gap-2">
              <Network className="size-6 text-emerald-400" />
              <span className="text-base font-bold text-emerald-400">
                NO EXFILTRATION
              </span>
            </div>

            <p className="mt-3 font-mono text-xs text-slate-500">
              No suspicious POST exfiltration events captured
            </p>

            <p className="mt-1 font-mono text-[10px] text-slate-500">
              {activeStreams} active runtime streams · {latentCount} latent targets
            </p>
          </>
        )}
      </div>
    </div>
  )
}

function LeftColumn({
  result,
  riskScore,
  verdict,
  isOfficialBank,
}: {
  result: any
  riskScore: number
  verdict: string
  isOfficialBank: boolean
}) {
  return (
    <div className="flex flex-col gap-6">
      <div className="glass-card rounded-2xl border border-slate-800 p-5">
        <h3 className="mb-4 flex items-center gap-2 font-mono text-sm font-semibold uppercase tracking-wider text-slate-200">
          <Activity className="size-4 text-cyan-400" /> Multi-Dimensional Risk Gauge
        </h3>
        <div className="flex items-center justify-center py-2">
          <RiskGauge
            value={Math.round(riskScore)}
            verdict={verdict}
            isOfficialBank={isOfficialBank}
          />
        </div>
        <div className="mt-2 grid grid-cols-4 gap-1 text-center font-mono text-[9px]">
          <span className="text-emerald-400">LOW 0-30</span>
          <span className="text-amber-400">MOD 31-60</span>
          <span className="text-orange-400">HIGH 61-80</span>
          <span className="text-rose-400">CRIT 81-100</span>
        </div>
      </div>

      <PermissionMatrix result={result} isOfficialBank={isOfficialBank} />
    </div>
  )
}

function PermissionMatrix({
  result,
  isOfficialBank,
}: {
  result: any
  isOfficialBank: boolean
}) {
  const permissions = result?.static?.permission_heatmap ?? []
  const [showAll, setShowAll] = useState(false)

  const highRiskPermissions = permissions.filter((p: any) => {
    const risk = String(p?.risk ?? "").toUpperCase()
    return risk === "CRITICAL" || risk === "HIGH"
  })

  const criticalCount = permissions.filter(
    (p: any) => String(p?.risk ?? "").toUpperCase() === "CRITICAL",
  ).length

  const displayedPermissions = showAll ? permissions : highRiskPermissions

  return (
    <div className="glass-card rounded-2xl border border-slate-800 p-5">
      <h3 className="mb-4 flex items-center gap-2 font-mono text-sm font-semibold uppercase tracking-wider text-slate-200">
        <CircleAlert className="size-4 text-rose-400" />
        Permission Matrix Heatmap
      </h3>

      <div className="mb-4 flex flex-wrap items-center gap-3 font-mono text-[10px]">
        <span className="text-rose-400">{highRiskPermissions.length} high-risk</span>
        <span className="text-slate-600">·</span>
        <span className="text-amber-400">{criticalCount} critical</span>
        <span className="text-slate-600">·</span>
        <span className="text-slate-500">{permissions.length} total declared</span>
      </div>

      <div className="flex flex-wrap gap-2">
        {displayedPermissions.length > 0 ? (
          displayedPermissions.map((p: any) => {
            const risk = String(p?.risk ?? "").toUpperCase()
            const isCritical = risk === "CRITICAL"
            const isHigh = risk === "HIGH"
            const isElevated = isCritical || isHigh
            const name =
              p?.short_name ??
              p?.permission?.split(".").pop() ??
              p?.permission ??
              "UNKNOWN"

            return (
              <span
                key={p?.permission ?? name}
                className={cn(
                  "inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 font-mono text-[11px]",
                  isCritical
                    ? "border border-rose-500/40 bg-rose-950/50 text-rose-400 shadow-[0_0_10px_-2px] shadow-rose-500/40"
                    : isHigh
                      ? "border border-amber-500/40 bg-amber-950/40 text-amber-300"
                      : "border border-slate-700 bg-slate-800/50 text-slate-400",
                )}
              >
                {isElevated && <AlertTriangle className="size-3" />}
                {name}
              </span>
            )
          })
        ) : (
          <span className="font-mono text-[11px] text-slate-500">
            No declared permissions returned by Module 1.
          </span>
        )}
      </div>

      {permissions.length > highRiskPermissions.length && (
        <button
          type="button"
          onClick={() => setShowAll((value) => !value)}
          className="mt-4 rounded-md border border-slate-700 bg-slate-800/50 px-3 py-1.5 font-mono text-[10px] text-slate-400 transition-colors hover:border-slate-600 hover:text-slate-300"
        >
          {showAll
            ? "SHOW HIGH-RISK ONLY"
            : `SHOW ALL ${permissions.length} PERMISSIONS`}
        </button>
      )}

      <p className="mt-4 font-mono text-[10px] text-slate-500">
        <span className="text-rose-400">{highRiskPermissions.length} high-risk permissions</span>{" "}
        detected · <span className="text-amber-400">{criticalCount} critical</span> ·{" "}
        {isOfficialBank
          ? "verified official banking app; permissions require contextual audit."
          : "capable of SMS interception, accessibility hijack & overlay attacks."}
      </p>
    </div>
  )
}

function RightColumn({ result }: { result?: any }) {
  const customStoryboard =
    result?.social?.storyboard ??
    result?.social?.screenplay ??
    result?.storyboard ??
    STORYBOARD

  const [activeStepId, setActiveStepId] = useState<number>(1)

  const activeStep =
    customStoryboard.find((s: any) => (s.id ?? s.step) === activeStepId) ||
    customStoryboard[0]

  const detectedBrand =
    result?.social?.app_name ||
    result?.social?.brand_name ||
    result?.static?.app_name ||
    result?.static?.authenticity?.bank_name ||
    result?.static?.package_name?.split(".").pop() ||
    "Application"

  return (
    <div className="glass-card flex flex-col rounded-2xl border border-slate-800 p-5">
      <h3 className="mb-4 flex items-center gap-2 font-mono text-sm font-semibold uppercase tracking-wider text-slate-200">
        <Terminal className="size-4 text-cyan-400" /> Social Engineering Screenplay
      </h3>

      <div className="grid grid-cols-1 gap-5 sm:grid-cols-[1fr_auto]">
        <ol className="relative flex flex-col gap-1">
          {customStoryboard.map((s: any, i: number) => {
            const stepNumber = s.id ?? s.step ?? i + 1
            const isActive = activeStepId === stepNumber
            return (
              <li key={stepNumber} className="relative pl-7">
                {i < customStoryboard.length - 1 && (
                  <span className="absolute left-[10px] top-7 h-[calc(100%-12px)] w-px bg-slate-700" />
                )}
                <button
                  type="button"
                  onClick={() => setActiveStepId(stepNumber)}
                  className="group flex w-full items-start gap-3 rounded-lg py-2 text-left"
                >
                  <span
                    className={cn(
                      "absolute left-0 top-2.5 flex size-5 items-center justify-center rounded-full border font-mono text-[9px] font-bold transition-all",
                      isActive
                        ? "border-cyan-400 bg-cyan-400 text-slate-950 shadow-[0_0_10px_1px] shadow-cyan-400/60"
                        : "border-slate-600 bg-slate-900 text-slate-400 group-hover:border-slate-500",
                    )}
                  >
                    {stepNumber}
                  </span>
                  <span>
                    <span
                      className={cn(
                        "block text-sm font-medium transition-colors",
                        isActive ? "text-cyan-400" : "text-slate-300",
                      )}
                    >
                      {s.title}
                    </span>
                    <span className="block text-[11px] text-slate-500">
                      {s.subtitle || s.description}
                    </span>
                  </span>
                </button>
              </li>
            )
          })}
        </ol>

        <PhoneFrame activeStep={activeStep} stepId={activeStepId} brandName={detectedBrand} />
      </div>
    </div>
  )
}

function MitmConsole({ dynamic }: { dynamic?: any }) {
  const scrollRef = useRef<HTMLDivElement>(null)
  const rawConsole = dynamic?.mitm_console ?? []
  const hasRealLogs = Array.isArray(rawConsole) && rawConsole.length > 0
  const logs = hasRealLogs ? rawConsole : MITM_LOG

  const [lines, setLines] = useState(0)

  useEffect(() => {
    setLines(0)
    if (!logs.length) return
    const step = Math.max(1, Math.floor(logs.length / 15))
    const t = setInterval(() => {
      setLines((n) => {
        if (n + step >= logs.length) {
          clearInterval(t)
          return logs.length
        }
        return n + step
      })
    }, 50)
    return () => clearInterval(t)
  }, [logs])

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" })
  }, [lines])

  return (
    <div className="glass-card rounded-2xl border border-slate-800 p-5">
      <h3 className="mb-4 flex items-center gap-2 font-mono text-sm font-semibold uppercase tracking-wider text-slate-200">
        <Network className="size-4 text-rose-400" /> Raw mitmproxy Interception Console
        <span className="ml-auto flex items-center gap-1.5 font-mono text-[10px] text-rose-400">
          <span className="size-2 rounded-full bg-rose-500 animate-pulse-dot" />
          {hasRealLogs ? `CAPTURED (${logs.length} FLOWS)` : "SAMPLE CAPTURE"}
        </span>
      </h3>
      <div
        ref={scrollRef}
        className="terminal-scroll h-56 space-y-2 overflow-y-auto rounded-lg border border-slate-800 bg-slate-950/80 p-4 font-mono text-xs"
      >
        {logs.slice(0, lines).map((item: any, i: number) => {
          const time = item.timestamp ?? item.time ?? "00:00:00.000"
          let text = item.raw_line ?? item.text ?? ""
          if (typeof text === "string" && time && text.includes(time)) {
            text = text.replace(time, "").trim()
          }
          if (typeof text === "string" && text.startsWith("🔴")) {
            text = text.replace("🔴", "").trim()
          }
          const isCritical = Boolean(item.is_alarm ?? item.critical)

          return (
            <div
              key={i}
              className={cn(
                "flex gap-2 leading-relaxed",
                isCritical
                  ? "rounded border border-red-500/30 bg-red-950/40 p-2 text-red-400 shadow-[0_0_14px_-4px] shadow-red-500/50 font-semibold"
                  : "text-slate-400",
              )}
            >
              <span className="shrink-0 text-slate-600">{time}</span>
              <span className="flex-1 break-words">{text}</span>
            </div>
          )
        })}
        {lines >= logs.length && (
          <div className="text-slate-600">
            {"// listener active — dynamic session telemetry synchronized"}
          </div>
        )}
      </div>
    </div>
  )
}

function RuntimeDelta({ dynamic }: { dynamic?: any }) {
  const rawDelta = dynamic?.behavior_delta
  const hasRealDelta = Array.isArray(rawDelta) && rawDelta.length > 0
  const deltaList = hasRealDelta ? rawDelta : RUNTIME_DELTA

  return (
    <div className="glass-card rounded-2xl border border-slate-800 p-5">
      <h3 className="mb-1 flex items-center gap-2 font-mono text-sm font-semibold uppercase tracking-wider text-slate-200">
        <GitBranch className="size-4 text-cyan-400" /> Static vs Runtime Behavior Delta
      </h3>
      <p className="mb-4 text-[11px] text-slate-500">
        Declared Manifest Permissions vs Verified Runtime Execution Logs — exposing obfuscated hidden execution paths.
      </p>
      <div className="overflow-x-auto">
        <table className="w-full text-left font-mono text-xs">
          <thead>
            <tr className="border-b border-slate-800 text-slate-500">
              <th className="px-3 py-2 font-medium">Permission / Capability</th>
              <th className="px-3 py-2 font-medium">Declared</th>
              <th className="px-3 py-2 font-medium">Runtime</th>
              <th className="px-3 py-2 font-medium">Analyst Note</th>
            </tr>
          </thead>
          <tbody>
            {deltaList.map((r: any, idx: number) => {
              const perm = r.permission ?? `CAPABILITY_${idx}`
              const isDeclared =
                typeof r.declared_bool === "boolean"
                  ? r.declared_bool
                  : r.declared === "YES" || Boolean(r.declared)
              const isRuntime =
                typeof r.runtime_bool === "boolean"
                  ? r.runtime_bool
                  : r.runtime === "YES" || Boolean(r.runtime)
              const note = r.analyst_note ?? r.note ?? ""
              const hidden =
                r.status_tag === "HIDDEN_THREAT" || (!isDeclared && isRuntime)
              const decoy =
                r.status_tag === "DECOY" || (isDeclared && !isRuntime)

              return (
                <tr key={perm + idx} className="border-b border-slate-800/60">
                  <td className="px-3 py-2.5 text-slate-300">{perm}</td>
                  <td className="px-3 py-2.5">
                    <Cell on={isDeclared} />
                  </td>
                  <td className="px-3 py-2.5">
                    <Cell on={isRuntime} alarm={hidden} />
                  </td>
                  <td
                    className={cn(
                      "px-3 py-2.5",
                      hidden
                        ? "text-rose-400 font-semibold"
                        : decoy
                          ? "text-amber-400"
                          : "text-slate-400",
                    )}
                  >
                    {hidden && "⚠ "}
                    {note}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function Cell({ on, alarm }: { on: boolean; alarm?: boolean }) {
  return (
    <span
      className={cn(
        "inline-block rounded px-2 py-0.5 text-[10px] font-bold",
        on
          ? alarm
            ? "bg-rose-500/20 text-rose-400"
            : "bg-emerald-500/15 text-emerald-400"
          : "bg-slate-800 text-slate-500",
      )}
    >
      {on ? "YES" : "NO"}
    </span>
  )
}