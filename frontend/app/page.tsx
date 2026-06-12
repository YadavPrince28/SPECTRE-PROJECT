"use client"

import { useState } from "react"
import { Sidebar, type ViewId } from "@/components/spectre/sidebar"
import { IngestionHub } from "@/components/spectre/ingestion-hub"
import { AnalysisTerminal } from "@/components/spectre/analysis-terminal"
import { GenAISuite } from "@/components/spectre/genai-suite"

export default function Page() {
  const [view, setView] = useState<ViewId>("ingestion")
  const [analyzed, setAnalyzed] = useState(false)
  const [result, setResult]     = useState<any>(null)

  function handleNavigate(id: ViewId) {
    if ((id === "analysis" || id === "genai") && !analyzed) return
    setView(id)
  }

  function handleComplete(data: any) {
    setResult(data)
    setAnalyzed(true)
    setView("analysis")
  }

  return (
    <div className="flex h-screen overflow-hidden bg-background text-foreground">
      <Sidebar active={view} onNavigate={handleNavigate} analyzed={analyzed} />
      <main className="relative flex-1 overflow-y-auto">
        <div className="spectre-grid-bg pointer-events-none absolute inset-0 opacity-30" />
        <div className="relative mx-auto w-full max-w-7xl px-6 py-8 lg:px-10">
          {view === "ingestion" && (<IngestionHub onComplete={handleComplete} />)}
          {view === "analysis" && analyzed && <AnalysisTerminal result={result} />}
          {view === "genai" && analyzed &&  (<GenAISuite result={result} />)}
        </div>
      </main>
    </div>
  )
}
