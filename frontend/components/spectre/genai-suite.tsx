"use client"

import { useState } from "react"
import {
  ArrowRight,
  Braces,
  Brain,
  Code2,
  FileText,
  Workflow,
} from "lucide-react"
import { cn } from "@/lib/utils"
import { KILL_CHAIN, SMALI_SNIPPET } from "@/lib/spectre-data"

type Tab = "brief" | "code" | "killchain"

const TABS: { id: Tab; label: string; icon: typeof FileText }[] = [
  { id: "brief", label: "Fraud Investigator Brief", icon: FileText },
  { id: "code", label: "Decompiled Code Interpreter", icon: Code2 },
  { id: "killchain", label: "7-Stage Fraud Kill Chain", icon: Workflow },
]

export function GenAISuite({result}: {result: any}) {
  const investigatorBrief = result?.genai?.investigator_brief ?? null
  const killChainData = result?.genai?.kill_chain ?? null
  const codeExplanation = result?.genai?.code_explanation ?? null
  const [tab, setTab] = useState<Tab>("brief")

  return (
    <div className="flex flex-col gap-6">
      <Header />
      <ActionBar />

      {/* tab switcher */}
      <div className="glass-card rounded-2xl border border-slate-800 p-1.5">
        <div className="grid grid-cols-1 gap-1 sm:grid-cols-3">
          {TABS.map((t) => {
            const isActive = tab === t.id
            return (
              <button
                key={t.id}
                type="button"
                onClick={() => setTab(t.id)}
                className={cn(
                  "flex items-center justify-center gap-2 rounded-xl px-4 py-2.5 text-sm font-medium transition-all",
                  isActive
                    ? "bg-cyan-400/10 text-cyan-400 ring-1 ring-cyan-400/40"
                    : "text-slate-400 hover:bg-slate-800/50 hover:text-slate-200",
                )}
              >
                <t.icon className="size-4" />
                {t.label}
              </button>
            )
          })}
        </div>
      </div>

      <div className="glass-card rounded-2xl border border-slate-800 p-6">
        {tab === "brief" && <InvestigatorBrief />}
        {tab === "code" && <CodeInterpreter />}
        {tab === "killchain" && <KillChain />}
      </div>
    </div>
  )
}

function Header() {
  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-center gap-2">
        <span className="rounded-md border border-cyan-400/30 bg-cyan-400/10 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-cyan-400">
          View 03
        </span>
        <h2 className="text-xl font-semibold text-slate-100">GenAI Intelligence Suite</h2>
      </div>
      <p className="text-sm text-slate-500">
        Multi-document synthesis powered by Claude Intelligence Core — court-ready briefings, code interpretation, and attack reconstruction.
      </p>
    </div>
  )
}

function ActionBar() {
  return (
    <div className="glass-card flex flex-col gap-4 rounded-2xl border border-slate-800 p-5 lg:flex-row lg:items-center lg:justify-between">
      <div className="flex items-center gap-2 text-sm text-slate-400">
        <Brain className="size-5 text-cyan-400" />
        <span>
          <span className="font-mono text-[10px] uppercase tracking-wider text-emerald-400">
            Compliance:
          </span>{" "}
          Document Format Conforms to{" "}
          <span className="text-slate-200">RBI Master Circular Section 7.4</span> Incident Reporting Standard
        </span>
      </div>
      <div className="flex flex-wrap gap-3">
        <button className="inline-flex items-center gap-2 rounded-lg bg-rose-500 px-4 py-2 text-sm font-semibold text-white transition hover:bg-rose-400">
          <FileText className="size-4" /> Export Court-Admissible PDF Briefing
        </button>
        <button className="inline-flex items-center gap-2 rounded-lg border border-slate-700 px-4 py-2 text-sm font-medium text-slate-300 transition hover:border-slate-600 hover:text-slate-100">
          <Braces className="size-4" /> Download JSON Schema Logs
        </button>
      </div>
    </div>
  )
}

function InvestigatorBrief() {
  return (
    <article className="prose-invert max-w-none space-y-5 text-sm leading-relaxed text-slate-300">
      <div>
        <h3 className="text-lg font-bold text-slate-100">Executive Summary</h3>
        <p className="mt-2 text-slate-400">
          The submitted artifact{" "}
          <span className="font-mono text-cyan-400">uniontrust_secure_v3.2.apk</span> is a high-confidence
          banking trojan belonging to the <strong className="text-slate-200">DroidKungFu</strong> lineage. It
          impersonates UnionTrust mobile banking to harvest credentials and intercept OTP tokens, achieving a
          composite risk vector of <strong className="text-rose-400">94/100 (Critical Compromise)</strong>.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <Stat label="Targeted Institution" value="UnionTrust Bank" />
        <Stat label="Est. Accounts at Risk" value="312 contacts" />
        <Stat label="C2 Jurisdiction" value="RU (185.220.101.44)" />
      </div>

      <div>
        <h3 className="text-base font-bold text-slate-100">Key Findings</h3>
        <ul className="mt-2 space-y-2">
          {[
            "Abuses BIND_ACCESSIBILITY_SERVICE to perform overlay attacks and automated tap injection.",
            "Silently intercepts and forwards SMS OTPs to a hardcoded C2 endpoint before user notification.",
            "Employs runtime reflection to load SEND_SMS and RECORD_AUDIO capabilities absent from the manifest.",
            "Exfiltrates Customer ID, MPIN, and full contact list to api.fraudserver.ru over self-signed TLS.",
          ].map((f) => (
            <li key={f} className="flex gap-2 text-slate-400">
              <span className="mt-1.5 size-1.5 shrink-0 rounded-full bg-rose-400" />
              {f}
            </li>
          ))}
        </ul>
      </div>

      <div>
        <h3 className="text-base font-bold text-slate-100">Recommended Mitigation Procedures</h3>
        <ol className="mt-2 list-decimal space-y-2 pl-5 text-slate-400 marker:font-mono marker:text-cyan-400">
          <li>Blocklist C2 domains/IPs (api.fraudserver.ru, 185.220.101.44) at the network egress layer.</li>
          <li>Freeze and flag the implicated beneficiary account (1234567890) for transaction review.</li>
          <li>Issue customer advisory regarding the smishing campaign and fraudulent APK distribution.</li>
          <li>Deploy server-side step-up authentication independent of device-bound SMS OTP.</li>
        </ol>
      </div>
    </article>
  )
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
      <p className="font-mono text-[10px] uppercase tracking-wider text-slate-500">{label}</p>
      <p className="mt-1 font-semibold text-slate-100">{value}</p>
    </div>
  )
}

function CodeInterpreter() {
  return (
    <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
      <div>
        <div className="mb-2 flex items-center gap-2 font-mono text-xs text-slate-400">
          <Code2 className="size-4 text-cyan-400" /> Hook.smali · interceptOtp()
        </div>
        <pre className="terminal-scroll overflow-x-auto rounded-xl border border-slate-800 bg-slate-950/80 p-4 font-mono text-[11px] leading-relaxed">
          <code>
            {SMALI_SNIPPET.split("\n").map((line, i) => (
              <div key={i} className="flex gap-3">
                <span className="select-none text-slate-700">{String(i + 1).padStart(2, "0")}</span>
                <span className={cn(highlight(line))}>{line}</span>
              </div>
            ))}
          </code>
        </pre>
      </div>

      <div>
        <div className="mb-2 flex items-center gap-2 font-mono text-xs text-slate-400">
          <Brain className="size-4 text-cyan-400" /> Plain-English Interpretation
        </div>
        <div className="space-y-4 rounded-xl border border-slate-800 bg-slate-900/60 p-4 text-sm text-slate-300">
          <p>
            This method registers a broadcast receiver for the{" "}
            <span className="font-mono text-rose-400">SMS_RECEIVED</span> system event. Every incoming text
            message triggers it <em>before</em> the legitimate messaging app.
          </p>
          <p>
            It extracts the raw PDU (the SMS payload) via{" "}
            <span className="font-mono text-cyan-400">extractPdu()</span>, then immediately POSTs the contents
            — including any banking OTP — to{" "}
            <span className="font-mono text-rose-400">https://api.fraudserver.ru/sms</span>.
          </p>
          <div className="rounded-lg border border-amber-500/30 bg-amber-950/30 p-3 text-amber-300">
            <strong className="text-amber-400">Bank Counter-measure:</strong> Migrate OTP delivery to a
            push-based, app-attested channel and detect default-SMS-handler hijacking at login.
          </div>
        </div>
      </div>
    </div>
  )
}

function highlight(line: string) {
  if (line.includes("fraudserver") || line.includes("post")) return "text-rose-400"
  if (line.trim().startsWith(".method") || line.trim().startsWith(".end")) return "text-cyan-400"
  if (line.includes("const-string")) return "text-amber-300"
  if (line.trim().startsWith("invoke")) return "text-slate-200"
  return "text-slate-500"
}

function KillChain() {
  return (
    <div className="space-y-4">
      <p className="text-sm text-slate-400">
        Sequenced reconstruction of the end-to-end attack — from initial lure to financial extradition.
      </p>
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        {KILL_CHAIN.map((s, i) => (
          <div
            key={s.stage}
            className="relative flex gap-4 rounded-xl border border-slate-800 bg-slate-900/60 p-4"
          >
            <div
              className={cn(
                "flex size-9 shrink-0 items-center justify-center rounded-lg font-mono text-sm font-bold",
                s.stage >= 5
                  ? "bg-rose-500/15 text-rose-400"
                  : s.stage >= 3
                    ? "bg-amber-500/15 text-amber-400"
                    : "bg-cyan-400/15 text-cyan-400",
              )}
            >
              {s.stage}
            </div>
            <div className="flex-1">
              <div className="flex items-center gap-1.5">
                <h4 className="font-semibold text-slate-100">{s.title}</h4>
                {i < KILL_CHAIN.length - 1 && (
                  <ArrowRight className="size-3.5 text-slate-600" />
                )}
              </div>
              <p className="mt-1 text-xs leading-relaxed text-slate-400">{s.detail}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
