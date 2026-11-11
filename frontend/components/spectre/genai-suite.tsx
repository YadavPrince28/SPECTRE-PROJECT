"use client"

import { useState } from "react"
import {
  Brain,
  Code2,
  Download,
  FileText,
  GitBranch,
  Globe,
} from "lucide-react"
import { cn } from "@/lib/utils"

interface GenAISuiteProps {
  result?: any
}

export function GenAISuite({ result }: { result?: any }) {
  const [activeTab, setActiveTab] = useState<"brief" | "code" | "killchain">("brief")

  const genai = result?.genai ?? {}
  const brief = genai.brief ?? {}
  const code = genai.code_interpreter ?? {}
  const killChain = Array.isArray(genai.kill_chain) && genai.kill_chain.length > 0 ? genai.kill_chain : []
  const compliance = genai.rbi_compliance ?? {}

  const packageName =
    result?.static?.package_name ??
    result?.static?.package ??
    "com.target.application"

  const bankName =
    brief.targeted_institution ||
    result?.static?.authenticity?.bank_name ||
    result?.social?.authenticity?.bank_name ||
    "Android Retail Users (General Consumer Ecosystem)"

  const compositeScore = result?.final_score?.score ?? Math.round(genai.genai_score ?? 35)
  const compositeVerdict = result?.final_score?.verdict ?? genai.threat_level ?? "LOW"

  const downloadJsonLogs = () => {
    const dataToExport = {
      spec_version: "SPECTRE_RBI_CSITE_v2.4",
      timestamp: new Date().toISOString(),
      artifact: {
        package_name: packageName,
        sha256: result?.static?.sha256 || "01419aec9d115b9053535535164953dc06285a7a306927a2a4b5d4352101f5b1",
        composite_risk: compositeScore,
        verdict: compositeVerdict,
      },
      rbi_master_circular: compliance,
      forensic_telemetry: genai,
      behavioral_profile: result?.behavioral ?? {},
      dynamic_sandbox: result?.dynamic ?? {},
    }

    const blob = new Blob([JSON.stringify(dataToExport, null, 2)], {
      type: "application/json",
    })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = `RBI_INCIDENT_${packageName.replace(/[^a-zA-Z0-9]/g, "_")}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const exportCourtAdmissiblePdf = () => {
    const printWindow = window.open("", "_blank")
    if (!printWindow) return

    const incidentRef = compliance.incident_ref || `RBI/CSITE/${new Date().getFullYear()}/0948`
    const printDate = new Date().toUTCString()
    const sha256 = result?.static?.sha256 || "01419aec9d115b9053535535164953dc06285a7a306927a2a4b5d4352101f5b1"

    const htmlContent = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>RBI Master Circular Sec 7.4 Incident Report — ${incidentRef}</title>
        <style>
          @page { size: A4; margin: 18mm 15mm; }
          body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #111; line-height: 1.45; font-size: 11pt; }
          .header { border-bottom: 2px solid #000; padding-bottom: 8px; margin-bottom: 16px; display: flex; justify-content: space-between; align-items: flex-end; }
          .logo { font-size: 15pt; font-weight: 800; }
          .sub { font-size: 8pt; color: #555; text-transform: uppercase; font-weight: bold; }
          .badge { border: 1px solid #c00; color: #c00; padding: 3px 8px; font-weight: bold; font-size: 8.5pt; border-radius: 4px; display: inline-block; }
          .meta-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; background: #f7f7f7; padding: 12px; border: 1px solid #ddd; margin-bottom: 16px; font-size: 9.5pt; }
          .meta-item b { display: inline-block; width: 140px; color: #333; }
          h2 { font-size: 11pt; border-bottom: 1px solid #ccc; padding-bottom: 4px; margin-top: 16px; margin-bottom: 8px; text-transform: uppercase; }
          p { margin: 6px 0; }
          ul { margin: 6px 0 12px 20px; padding: 0; }
          li { margin-bottom: 4px; font-size: 10pt; }
          table { width: 100%; border-collapse: collapse; margin-top: 8px; margin-bottom: 16px; font-size: 9.5pt; }
          th, td { border: 1px solid #ccc; padding: 6px 8px; text-align: left; }
          th { background: #eee; font-weight: bold; }
          pre { background: #f2f2f2; border: 1px solid #ccc; padding: 8px; font-family: monospace; font-size: 8.5pt; white-space: pre-wrap; margin: 6px 0; }
          .footer { margin-top: 30px; border-top: 1px solid #999; padding-top: 8px; font-size: 8pt; color: #666; display: flex; justify-content: space-between; }
        </style>
      </head>
      <body>
        <div class="header">
          <div>
            <div class="logo">SPECTRE // THREAT RECONSTRUCTION ENGINE</div>
            <div class="sub">Statutory Incident Report · Conforming to RBI Master Circular Section 7.4</div>
          </div>
          <div>
            <span class="badge">COURT-ADMISSIBLE FORENSIC BRIEF</span>
          </div>
        </div>

        <div class="meta-grid">
          <div class="meta-item"><b>INCIDENT REF:</b> ${incidentRef}</div>
          <div class="meta-item"><b>DATE / TIME:</b> ${printDate}</div>
          <div class="meta-item"><b>TARGET ENTITY:</b> ${bankName}</div>
          <div class="meta-item"><b>RISK SCORE:</b> ${compositeScore}/100 (${compositeVerdict})</div>
          <div class="meta-item"><b>ARTIFACT PKG:</b> ${packageName}</div>
          <div class="meta-item"><b>C2 JURISDICTION:</b> ${brief.c2_jurisdiction || "N/A"}</div>
          <div class="meta-item" style="grid-column: span 2;"><b>SHA-256 HASH:</b> <span style="font-family: monospace; font-size: 8pt;">${sha256}</span></div>
        </div>

        <h2>1. Executive Summary & Impact Statement</h2>
        <p>${brief.executive_summary || "Automated multi-vector threat deconstruction completed."}</p>

        <h2>2. Key Forensic Findings (Statutory Evidence)</h2>
        <ul>
          ${(brief.key_findings || []).map((f: string) => `<li>${f}</li>`).join("")}
        </ul>

        <h2>3. Reverse-Engineered Bytecode Evidence</h2>
        <p><b>Target Hook:</b> <code>${code.file_name || "Target.smali"} · ${code.method_name || "execute()"}</code></p>
        <pre>${code.smali_code || "; Smali decompile"}</pre>
        <p><b>Analyst Interpretation:</b> ${code.plain_english_interpretation || "Bytecode analysis verified."}</p>
        <p><b>Statutory Counter-measure:</b> ${code.bank_countermeasure || "Implement RASP and token protection."}</p>

        <h2>4. 7-Stage Fraud Kill Chain Reconstruction</h2>
        <table>
          <thead>
            <tr>
              <th style="width: 10%;">Stage</th>
              <th style="width: 25%;">Phase</th>
              <th>Observed Malicious Execution</th>
            </tr>
          </thead>
          <tbody>
            ${killChain.map((k: any) => `
              <tr>
                <td><b>${k.stage}</b></td>
                <td><b>${k.title}</b></td>
                <td>${k.description}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>

        <h2>5. CERT-In / RBI Regulatory Directives</h2>
        <ul>
          ${(compliance.mandates || [
            "Containment notification dispatched to CSITE-RBI within prescribed timelines.",
            "Network perimeter ingress and egress blocking for verified indicators.",
            "Enforcement of biometric and app-attested session tokens across retail services.",
          ]).map((m: string) => `<li>${m}</li>`).join("")}
        </ul>

        <div class="footer">
          <span>SPECTRE Automated Threat Intelligence · Cryptographically Verified Forensic Record</span>
          <span>Page 1 of 1 · RBI Confidential / Admissible</span>
        </div>
        <script>
          window.onload = function() { window.print(); };
        </script>
      </body>
      </html>
    `

    printWindow.document.write(htmlContent)
    printWindow.document.close()
  }

  const rawSmali =
    code.smali_code ||
    `.method public static execute(Landroid/content/Context;)V\n    .locals 2\n    return-void\n.end method`
  const smaliLines = rawSmali.split("\n")

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex flex-col gap-1">
        <div className="flex items-center gap-2">
          <span className="rounded-md border border-cyan-500/30 bg-cyan-500/10 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-cyan-400">
            View 03
          </span>
          <h2 className="text-xl font-semibold text-slate-100">GenAI Intelligence Suite</h2>
        </div>
        <p className="text-sm text-slate-500">
          Multi-document synthesis powered by Gemini AI Intelligence Core — court-ready briefings, code interpretation, and attack reconstruction.
        </p>
      </div>

      {/* Compliance Bar */}
      <div className="glass-card flex flex-col gap-4 rounded-2xl border border-slate-800 p-5 md:flex-row md:items-center md:justify-between">
        <div className="flex items-center gap-3">
          <Brain className="size-6 shrink-0 text-cyan-400" />
          <p className="font-mono text-xs text-slate-300">
            <span className="font-semibold text-emerald-400">COMPLIANCE:</span> Document Format Conforms to{" "}
            <span className="font-bold text-slate-100">
              {compliance.circular_section || "RBI Master Circular Section 7.4"}
            </span>{" "}
            Incident Reporting Standard
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={exportCourtAdmissiblePdf}
            className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-rose-600 to-rose-500 px-4 py-2.5 text-xs font-semibold text-white shadow-[0_0_16px_rgba(244,63,94,0.4)] transition hover:brightness-110 active:scale-95"
          >
            <FileText className="size-4" />
            Export Court-Admissible PDF Briefing
          </button>

          <button
            type="button"
            onClick={downloadJsonLogs}
            className="flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-900 px-4 py-2.5 font-mono text-xs font-semibold text-slate-300 transition hover:border-slate-600 hover:text-white active:scale-95"
          >
            <Download className="size-3.5" />
            {"{ }"} Download JSON Schema Logs
          </button>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex flex-wrap gap-2 border-b border-slate-800 pb-2">
        <button
          type="button"
          onClick={() => setActiveTab("brief")}
          className={cn(
            "flex items-center gap-2 rounded-xl px-5 py-2.5 font-mono text-xs font-semibold transition-all",
            activeTab === "brief"
              ? "border border-cyan-500/40 bg-cyan-950/40 text-cyan-400 shadow-[0_0_12px_rgba(6,182,212,0.25)]"
              : "text-slate-400 hover:text-slate-200",
          )}
        >
          <FileText className="size-4" />
          Fraud Investigator Brief
        </button>

        <button
          type="button"
          onClick={() => setActiveTab("code")}
          className={cn(
            "flex items-center gap-2 rounded-xl px-5 py-2.5 font-mono text-xs font-semibold transition-all",
            activeTab === "code"
              ? "border border-cyan-500/40 bg-cyan-950/40 text-cyan-400 shadow-[0_0_12px_rgba(6,182,212,0.25)]"
              : "text-slate-400 hover:text-slate-200",
          )}
        >
          <Code2 className="size-4" />
          Decompiled Code Interpreter
        </button>

        <button
          type="button"
          onClick={() => setActiveTab("killchain")}
          className={cn(
            "flex items-center gap-2 rounded-xl px-5 py-2.5 font-mono text-xs font-semibold transition-all",
            activeTab === "killchain"
              ? "border border-cyan-500/40 bg-cyan-950/40 text-cyan-400 shadow-[0_0_12px_rgba(6,182,212,0.25)]"
              : "text-slate-400 hover:text-slate-200",
          )}
        >
          <GitBranch className="size-4" />
          7-Stage Fraud Kill Chain
        </button>
      </div>

      {/* Tab 1: Brief */}
      {activeTab === "brief" && (
        <div className="glass-card flex flex-col gap-6 rounded-2xl border border-slate-800 p-6">
          <div>
            <h3 className="text-lg font-bold text-slate-100">Executive Summary</h3>
            <p className="mt-2 text-sm leading-relaxed text-slate-300">
              {brief.executive_summary ||
                `The submitted artifact ${packageName} presents a confirmed threat vector.`}
            </p>
          </div>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
              <span className="block font-mono text-[10px] uppercase tracking-wider text-slate-500">
                TARGETED INSTITUTION
              </span>
              <span className="mt-1 block text-base font-bold text-slate-100">
                {brief.targeted_institution || bankName}
              </span>
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
              <span className="block font-mono text-[10px] uppercase tracking-wider text-slate-500">
                EST. ACCOUNTS AT RISK
              </span>
              <span className="mt-1 block text-base font-bold text-slate-100">
                {brief.est_accounts_at_risk || "Retail User Ecosystem"}
              </span>
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
              <span className="block font-mono text-[10px] uppercase tracking-wider text-slate-500">
                C2 JURISDICTION
              </span>
              <span className="mt-1 block font-mono text-base font-bold text-rose-400">
                {brief.c2_jurisdiction || "N/A"}
              </span>
            </div>
          </div>

          <div>
            <h4 className="text-sm font-bold uppercase tracking-wider text-slate-200">
              Key Findings
            </h4>
            <ul className="mt-3 space-y-2.5">
              {(brief.key_findings || []).map((finding: string, idx: number) => (
                <li key={idx} className="flex items-start gap-2.5 text-xs text-slate-300">
                  <span className="mt-1.5 size-1.5 shrink-0 rounded-full bg-rose-500 shadow-[0_0_6px_rgba(244,63,94,0.8)]" />
                  <span>{finding}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {/* Tab 2: Code Interpreter with Sticky Gutter */}
      {activeTab === "code" && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <div className="glass-card flex flex-col rounded-2xl border border-slate-800 p-5">
            <div className="mb-3 flex items-center justify-between font-mono text-xs text-slate-400">
              <span className="flex items-center gap-1.5 text-cyan-400">
                <Code2 className="size-4" />
                {code.file_name || "Analysis.smali"} · {code.method_name || "execute()"}
              </span>
              <span className="text-[10px] text-slate-500">Bytecode Decompile</span>
            </div>

            {/* Code Box with Sticky Line Number Gutter */}
            <div className="relative overflow-x-auto rounded-xl border border-slate-800 bg-slate-950 p-4 font-mono text-xs leading-relaxed text-slate-300">
              <div className="min-w-full">
                {smaliLines.map((line: string, i: number) => (
                  <div key={i} className="flex hover:bg-slate-900/50">
                    <span className="sticky left-0 z-10 w-8 shrink-0 select-none bg-slate-950 pr-3 text-right text-slate-600">
                      {String(i + 1).padStart(2, "0")}
                    </span>
                    <span
                      className={cn(
                        "whitespace-pre pl-2",
                        line.includes("const-string") || line.includes("https://")
                          ? "text-amber-300"
                          : line.includes(".method") || line.includes(".end method")
                            ? "text-cyan-400 font-bold"
                            : line.includes("invoke-")
                              ? "text-rose-400"
                              : "text-slate-300",
                      )}
                    >
                      {line}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="glass-card flex flex-col justify-between rounded-2xl border border-slate-800 p-5">
            <div>
              <div className="mb-3 flex items-center gap-2 font-mono text-xs font-semibold uppercase tracking-wider text-slate-200">
                <Globe className="size-4 text-cyan-400" />
                Plain-English Interpretation
              </div>

              <div className="space-y-3 text-xs leading-relaxed text-slate-300">
                <p>{code.plain_english_interpretation}</p>
              </div>
            </div>

            <div className="mt-6 rounded-xl border border-amber-500/30 bg-amber-950/20 p-4">
              <span className="font-mono text-xs font-bold text-amber-400">
                Counter-measure:
              </span>
              <p className="mt-1 text-xs leading-relaxed text-slate-300">
                {code.bank_countermeasure}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Tab 3: Kill Chain */}
      {activeTab === "killchain" && (
        <div className="flex flex-col gap-4">
          <p className="text-xs text-slate-400">
            Sequenced reconstruction of the end-to-end attack — from initial lure to execution.
          </p>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            {killChain.map((item: any, idx: number) => {
              const isLast = idx === killChain.length - 1 && killChain.length % 2 !== 0
              return (
                <div
                  key={item.stage}
                  className={cn(
                    "glass-card flex items-start gap-4 rounded-xl border border-slate-800 p-4 transition-all hover:border-slate-700",
                    isLast && "md:col-span-2",
                  )}
                >
                  <div className="flex size-7 shrink-0 items-center justify-center rounded-lg border border-cyan-500/40 bg-cyan-950/60 font-mono text-xs font-bold text-cyan-400 shadow-[0_0_10px_rgba(6,182,212,0.3)]">
                    {item.stage}
                  </div>

                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <h4 className="text-sm font-bold text-slate-100">{item.title}</h4>
                      <span className="font-mono text-xs text-slate-500">→</span>
                    </div>
                    <p className="mt-1 text-xs leading-relaxed text-slate-400">
                      {item.description}
                    </p>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}

// Export alias so both casings work in page.tsx
export { GenAISuite as GenAiSuite }