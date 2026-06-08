"use client"

import { Brain, ShieldAlert, UploadCloud } from "lucide-react"
import { cn } from "@/lib/utils"

export type ViewId = "ingestion" | "analysis" | "genai"

const NAV_ITEMS: {
  id: ViewId
  label: string
  icon: typeof UploadCloud
}[] = [
  { id: "ingestion", label: "Ingestion Hub", icon: UploadCloud },
  { id: "analysis", label: "Advanced Analysis Terminal", icon: ShieldAlert },
  { id: "genai", label: "GenAI Intelligence Suite", icon: Brain },
]

export function Sidebar({
  active,
  onNavigate,
  analyzed,
}: {
  active: ViewId
  onNavigate: (id: ViewId) => void
  analyzed: boolean
}) {
  return (
    <aside className="flex h-full w-72 shrink-0 flex-col border-r border-slate-800 bg-sidebar">
      {/* Brand */}
      <div className="flex items-center gap-3 border-b border-slate-800 px-6 py-5">
        <div className="relative flex size-11 items-center justify-center rounded-xl border border-cyan-400/30 bg-cyan-400/10">
          <ShieldAlert className="size-6 text-cyan-400" />
          <span className="absolute inset-0 rounded-xl ring-1 ring-cyan-400/20" />
        </div>
        <div>
          <h1 className="font-mono text-lg font-bold tracking-[0.2em] text-slate-100">
            SPECTRE
          </h1>
          <p className="text-[10px] uppercase tracking-wider text-slate-500">
            Threat Reconstruction Engine
          </p>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex flex-1 flex-col gap-1 p-3">
        <p className="px-3 py-2 text-[10px] font-semibold uppercase tracking-widest text-slate-600">
          Operations
        </p>
        {NAV_ITEMS.map((item) => {
          const isActive = active === item.id
          const locked = item.id !== "ingestion" && !analyzed
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => onNavigate(item.id)}
              className={cn(
                "group relative flex items-center gap-3 rounded-lg px-3 py-2.5 text-left text-sm transition-all",
                isActive
                  ? "bg-slate-800/70 text-slate-100"
                  : "text-slate-400 hover:bg-slate-800/40 hover:text-slate-200",
              )}
            >
              <span
                className={cn(
                  "absolute left-0 top-1/2 h-7 w-[3px] -translate-y-1/2 rounded-r-full transition-all",
                  isActive
                    ? "bg-cyan-400 shadow-[0_0_12px_2px] shadow-cyan-400/60"
                    : "bg-transparent",
                )}
              />
              <item.icon
                className={cn(
                  "size-[18px] shrink-0 transition-colors",
                  isActive ? "text-cyan-400" : "text-slate-500 group-hover:text-slate-300",
                )}
              />
              <span className="flex-1 leading-tight">{item.label}</span>
              {locked && (
                <span className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-[9px] text-slate-500">
                  IDLE
                </span>
              )}
            </button>
          )
        })}
      </nav>

      {/* Telemetry widget */}
      <div className="m-3 rounded-xl border border-slate-800 bg-slate-900/60 p-3">
        <div className="mb-2 flex items-center gap-2">
          <span className="relative flex size-2.5">
            <span className="absolute inline-flex size-full rounded-full bg-emerald-500 animate-pulse-dot" />
            <span className="relative inline-flex size-2.5 rounded-full bg-emerald-500" />
          </span>
          <span className="font-mono text-[10px] font-semibold uppercase tracking-wider text-emerald-400">
            System Node: Live
          </span>
        </div>
        <p className="font-mono text-[10px] leading-relaxed text-slate-500">
          Sandbox Connection via Windows Native Environment
        </p>
      </div>
    </aside>
  )
}
