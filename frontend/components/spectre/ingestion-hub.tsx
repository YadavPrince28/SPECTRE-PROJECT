"use client"

import { useEffect, useRef, useState } from "react"
import {
  Bot,
  Brain,
  Cpu,
  FileArchive,
  FolderSearch,
  Loader2,
  Network,
  ScanLine,
  UploadCloud,
} from "lucide-react"
import { cn } from "@/lib/utils"
import { PIPELINE_STEPS, type PipelineStep } from "@/lib/spectre-data"

const TONE_STYLES: Record<PipelineStep["tone"], { color: string; icon: typeof Cpu }> = {
  system: { color: "text-slate-300", icon: Cpu },
  static: { color: "text-cyan-400", icon: ScanLine },
  dynamic: { color: "text-amber-400", icon: Bot },
  automation: { color: "text-amber-400", icon: Bot },
  network: { color: "text-rose-400", icon: Network },
  genai: { color: "text-cyan-400", icon: Brain },
}

export function IngestionHub({ onComplete }: { onComplete: () => void }) {
  const [status, setStatus] = useState<"idle" | "running" | "done">("idle")
  const [progress, setProgress] = useState(0)
  const [visibleSteps, setVisibleSteps] = useState(0)
  const [dragging, setDragging] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  function startPipeline(name?: string) {
    if (status === "running") return
    setStatus("running")
    setProgress(0)
    setVisibleSteps(0)
    if (name) setFileName(name)
  }

  const [fileName, setFileName] = useState("uniontrust_secure_v3.2.apk")

  useEffect(() => {
    if (status !== "running") return
    const stepTimers: ReturnType<typeof setTimeout>[] = []
    PIPELINE_STEPS.forEach((_, i) => {
      stepTimers.push(
        setTimeout(() => setVisibleSteps(i + 1), 600 + i * 900),
      )
    })
    const start = Date.now()
    const total = 600 + PIPELINE_STEPS.length * 900 + 600
    const interval = setInterval(() => {
      const pct = Math.min(100, Math.round(((Date.now() - start) / total) * 100))
      setProgress(pct)
      if (pct >= 100) {
        clearInterval(interval)
        setStatus("done")
        setTimeout(onComplete, 900)
      }
    }, 60)
    return () => {
      stepTimers.forEach(clearTimeout)
      clearInterval(interval)
    }
  }, [status, onComplete])

  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-6">
      <Header />

      {/* Dropzone */}
      <div
        onDragOver={(e) => {
          e.preventDefault()
          setDragging(true)
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault()
          setDragging(false)
          const f = e.dataTransfer.files?.[0]
          startPipeline(f?.name)
        }}
        className={cn(
          "glass-card relative flex flex-col items-center justify-center gap-5 overflow-hidden rounded-2xl border-2 border-dashed px-6 py-16 text-center transition-all",
          dragging
            ? "border-cyan-400 bg-cyan-400/5"
            : "border-slate-700 hover:border-slate-600",
        )}
      >
        <div className="spectre-grid-bg pointer-events-none absolute inset-0 opacity-40" />
        {status === "running" && (
          <div className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-400 to-transparent animate-scan" />
        )}

        <div className="relative">
          <div className="flex size-20 items-center justify-center rounded-2xl border border-cyan-400/30 bg-cyan-400/10">
            {status === "running" ? (
              <Loader2 className="size-9 animate-spin text-cyan-400" />
            ) : (
              <UploadCloud className="size-9 text-cyan-400" />
            )}
          </div>
          <span className="absolute -inset-2 -z-10 rounded-3xl bg-cyan-400/10 blur-xl" />
        </div>

        <div className="relative space-y-1">
          <p className="text-balance text-lg font-semibold text-slate-100">
            Drop suspicious banking APK archive here or browse local directories
          </p>
          <p className="font-mono text-xs text-slate-500">.apk file extensions only</p>
        </div>

        <div className="relative flex flex-wrap items-center justify-center gap-3">
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            className="inline-flex items-center gap-2 rounded-lg bg-cyan-400 px-4 py-2 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300"
          >
            <FolderSearch className="size-4" /> Browse Directory
          </button>
          <button
            type="button"
            onClick={() => startPipeline()}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-700 px-4 py-2 text-sm font-medium text-slate-300 transition hover:border-slate-600 hover:text-slate-100"
          >
            <FileArchive className="size-4" /> Use Sample APK
          </button>
          <input
            ref={fileInputRef}
            type="file"
            accept=".apk"
            className="hidden"
            onChange={(e) => startPipeline(e.target.files?.[0]?.name)}
          />
        </div>

        {status !== "idle" && (
          <div className="relative flex items-center gap-2 font-mono text-xs text-slate-400">
            <FileArchive className="size-3.5 text-cyan-400" />
            {fileName}
          </div>
        )}
      </div>

      {/* Pipeline telemetry + progress */}
      <div className="glass-card rounded-2xl border border-slate-800 p-5">
        <div className="mb-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Network className="size-4 text-cyan-400" />
            <h3 className="font-mono text-sm font-semibold uppercase tracking-wider text-slate-200">
              Live Pipeline Telemetry Stream
            </h3>
          </div>
          <span className="font-mono text-xs text-slate-500">{progress}%</span>
        </div>

        {/* Progress bar */}
        <div className="mb-5 h-2 w-full overflow-hidden rounded-full bg-slate-800">
          <div
            className="h-full rounded-full bg-gradient-to-r from-cyan-500 via-cyan-400 to-emerald-400 shadow-[0_0_12px] shadow-cyan-400/50 transition-all duration-200 ease-out"
            style={{ width: `${progress}%` }}
          />
        </div>

        {/* Console */}
        <div className="terminal-scroll max-h-64 space-y-2 overflow-y-auto rounded-lg border border-slate-800 bg-slate-950/70 p-4 font-mono text-xs">
          {status === "idle" ? (
            <p className="text-slate-600">{"// Awaiting APK ingestion — pipeline standing by..."}</p>
          ) : (
            PIPELINE_STEPS.slice(0, visibleSteps).map((step, i) => {
              const tone = TONE_STYLES[step.tone]
              const done = i < visibleSteps - 1 || status === "done"
              return (
                <div key={step.tag} className="flex items-start gap-2 leading-relaxed">
                  <tone.icon className={cn("mt-0.5 size-3.5 shrink-0", tone.color)} />
                  <span className={cn("font-semibold", tone.color)}>[{step.tag}]</span>
                  <span className="flex-1 text-slate-300">{step.message}</span>
                  <span className={cn("shrink-0", done ? "text-emerald-400" : "text-amber-400")}>
                    {done ? "OK" : "···"}
                  </span>
                </div>
              )
            })
          )}
          {status === "done" && (
            <div className="flex items-center gap-2 pt-1 text-emerald-400">
              <span className="font-semibold">[COMPLETE]</span>
              <span>Behavioral metrics serialized. Routing to Analysis Terminal...</span>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function Header() {
  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-center gap-2">
        <span className="rounded-md border border-cyan-400/30 bg-cyan-400/10 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-cyan-400">
          View 01
        </span>
        <h2 className="text-xl font-semibold text-slate-100">Ingestion Hub</h2>
      </div>
      <p className="text-sm text-slate-500">
        Submit a banking malware sample for static deconstruction, dynamic sandbox detonation, and GenAI synthesis.
      </p>
    </div>
  )
}
