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
  PERMISSIONS,
  RUNTIME_DELTA,
  STORYBOARD,
} from "@/lib/spectre-data"
import { RiskGauge } from "./risk-gauge"
import { PhoneFrame } from "./phone-frame"

export function AnalysisTerminal() {
  return (
    <div className="flex flex-col gap-6">
      <Header />
      <QuickMetrics />

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <LeftColumn />
        <RightColumn />
      </div>

      <MitmConsole />
      <RuntimeDelta />
    </div>
  )
}

function Header() {
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
        <span className="font-mono text-slate-400">uniontrust_secure_v3.2.apk</span>.
      </p>
    </div>
  )
}

function QuickMetrics() {
  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
      <div className="glass-card animate-breathe-crimson relative overflow-hidden rounded-2xl border border-rose-500/40 p-5">
        <p className="font-mono text-[10px] uppercase tracking-wider text-slate-400">
          Composite Risk Vector
        </p>
        <div className="mt-2 flex items-end gap-2">
          <span className="font-mono text-4xl font-bold text-rose-400">94</span>
          <span className="mb-1 font-mono text-sm text-slate-500">/100</span>
        </div>
        <span className="mt-3 inline-flex items-center gap-1 rounded-md bg-rose-500/15 px-2 py-1 font-mono text-[10px] font-bold tracking-wider text-rose-400">
          <CircleAlert className="size-3" /> CRITICAL COMPROMISE
        </span>
      </div>

      <div className="glass-card rounded-2xl border border-slate-800 p-5">
        <p className="font-mono text-[10px] uppercase tracking-wider text-slate-400">
          Behavioral Graph Match
        </p>
        <div className="mt-2 flex items-center gap-3">
          <GitBranch className="size-7 text-cyan-400" />
          <span className="text-lg font-semibold text-slate-100">DroidKungFu Family</span>
        </div>
        <p className="mt-3 font-mono text-xs text-slate-500">15% Graph Edit Distance</p>
      </div>

      <div className="glass-card rounded-2xl border border-amber-500/40 p-5">
        <p className="font-mono text-[10px] uppercase tracking-wider text-slate-400">
          Network Exfiltration Status
        </p>
        <div className="mt-2 flex items-center gap-2">
          <AlertTriangle className="size-6 text-amber-400" />
          <span className="text-base font-bold text-amber-400">LIVE INTERCEPT DISCOVERED</span>
        </div>
        <p className="mt-3 font-mono text-xs text-slate-500">C2 beacon active · 3 endpoints</p>
      </div>
    </div>
  )
}

function LeftColumn() {
  return (
    <div className="flex flex-col gap-6">
      <div className="glass-card rounded-2xl border border-slate-800 p-5">
        <h3 className="mb-4 flex items-center gap-2 font-mono text-sm font-semibold uppercase tracking-wider text-slate-200">
          <Activity className="size-4 text-cyan-400" /> Multi-Dimensional Risk Gauge
        </h3>
        <div className="flex items-center justify-center py-2">
          <RiskGauge value={94} />
        </div>
        <div className="mt-2 grid grid-cols-4 gap-1 text-center font-mono text-[9px]">
          <span className="text-emerald-400">LOW 0-30</span>
          <span className="text-amber-400">MOD 31-60</span>
          <span className="text-orange-400">HIGH 61-80</span>
          <span className="text-rose-400">CRIT 81-100</span>
        </div>
      </div>

      <PermissionMatrix />
    </div>
  )
}

function PermissionMatrix() {
  return (
    <div className="glass-card rounded-2xl border border-slate-800 p-5">
      <h3 className="mb-4 flex items-center gap-2 font-mono text-sm font-semibold uppercase tracking-wider text-slate-200">
        <CircleAlert className="size-4 text-rose-400" /> Permission Matrix Heatmap
      </h3>
      <div className="flex flex-wrap gap-2">
        {PERMISSIONS.map((p) => (
          <span
            key={p.name}
            className={cn(
              "inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 font-mono text-[11px]",
              p.critical
                ? "border border-red-500/30 bg-red-950/50 text-red-400 shadow-[0_0_10px_-2px] shadow-red-500/40"
                : "border border-slate-700 bg-slate-800/50 text-slate-400",
            )}
          >
            {p.critical && <AlertTriangle className="size-3" />}
            {p.name}
          </span>
        ))}
      </div>
      <p className="mt-4 font-mono text-[10px] text-slate-500">
        <span className="text-red-400">7 critical fraud permissions</span> detected · capable of SMS interception, accessibility hijack & overlay attacks.
      </p>
    </div>
  )
}

function RightColumn() {
  const [active, setActive] = useState(STORYBOARD[0])

  return (
    <div className="glass-card flex flex-col rounded-2xl border border-slate-800 p-5">
      <h3 className="mb-4 flex items-center gap-2 font-mono text-sm font-semibold uppercase tracking-wider text-slate-200">
        <Terminal className="size-4 text-cyan-400" /> Social Engineering Screenplay
      </h3>

      <div className="grid grid-cols-1 gap-5 sm:grid-cols-[1fr_auto]">
        {/* timeline stepper */}
        <ol className="relative flex flex-col gap-1">
          {STORYBOARD.map((s, i) => {
            const isActive = active.id === s.id
            return (
              <li key={s.id} className="relative pl-7">
                {i < STORYBOARD.length - 1 && (
                  <span className="absolute left-[10px] top-7 h-[calc(100%-12px)] w-px bg-slate-700" />
                )}
                <button
                  type="button"
                  onClick={() => setActive(s)}
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
                    {s.id}
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
                    <span className="block text-[11px] text-slate-500">{s.subtitle}</span>
                  </span>
                </button>
              </li>
            )
          })}
        </ol>

        {/* device viewport */}
        <PhoneFrame screen={active.device} />
      </div>
    </div>
  )
}

function MitmConsole() {
  const scrollRef = useRef<HTMLDivElement>(null)
  const [lines, setLines] = useState(0)

  useEffect(() => {
    const t = setInterval(() => {
      setLines((n) => (n < MITM_LOG.length ? n + 1 : n))
    }, 700)
    return () => clearInterval(t)
  }, [])

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" })
  }, [lines])

  return (
    <div className="glass-card rounded-2xl border border-slate-800 p-5">
      <h3 className="mb-4 flex items-center gap-2 font-mono text-sm font-semibold uppercase tracking-wider text-slate-200">
        <Network className="size-4 text-rose-400" /> Raw mitmproxy Interception Console
        <span className="ml-auto flex items-center gap-1.5 font-mono text-[10px] text-rose-400">
          <span className="size-2 rounded-full bg-rose-500 animate-pulse-dot" /> CAPTURING
        </span>
      </h3>
      <div
        ref={scrollRef}
        className="terminal-scroll h-56 space-y-2 overflow-y-auto rounded-lg border border-slate-800 bg-slate-950/80 p-4 font-mono text-xs"
      >
        {MITM_LOG.slice(0, lines).map((l, i) => (
          <div
            key={i}
            className={cn(
              "flex gap-2 leading-relaxed",
              l.critical
                ? "rounded border border-red-500/30 bg-red-950/40 p-2 text-red-400 shadow-[0_0_14px_-4px] shadow-red-500/50"
                : "text-slate-400",
            )}
          >
            <span className="shrink-0 text-slate-600">{l.time}</span>
            <span className="flex-1 break-words">{l.text}</span>
          </div>
        ))}
        {lines >= MITM_LOG.length && (
          <div className="text-slate-600">{"// listener active — awaiting next frame..."}</div>
        )}
      </div>
    </div>
  )
}

function RuntimeDelta() {
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
            {RUNTIME_DELTA.map((r) => {
              const hidden = !r.declared && r.runtime
              const decoy = r.declared && !r.runtime
              return (
                <tr key={r.permission} className="border-b border-slate-800/60">
                  <td className="px-3 py-2.5 text-slate-300">{r.permission}</td>
                  <td className="px-3 py-2.5">
                    <Cell on={r.declared} />
                  </td>
                  <td className="px-3 py-2.5">
                    <Cell on={r.runtime} alarm={hidden} />
                  </td>
                  <td
                    className={cn(
                      "px-3 py-2.5",
                      hidden ? "text-rose-400" : decoy ? "text-amber-400" : "text-slate-400",
                    )}
                  >
                    {hidden && "⚠ "}
                    {r.note}
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
