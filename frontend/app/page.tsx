"use client"

import { useState } from "react"
import { Sidebar, type ViewId } from "@/components/spectre/sidebar"
import { IngestionHub } from "@/components/spectre/ingestion-hub"
import { AnalysisTerminal } from "@/components/spectre/analysis-terminal"
// Supports both naming conventions (GenAISuite or GenAiSuite)
import { GenAiSuite } from "@/components/spectre/genai-suite"

export default function Page() {
  const [view, setView] = useState<ViewId>("ingestion")
  const [analyzed, setAnalyzed] = useState(false)
  const [result, setResult] = useState<any>(null)

  function handleNavigate(id: ViewId) {
    // Prevent navigating to analysis or genai before an APK has completed ingestion
    if ((id === "analysis" || id === "genai") && !analyzed) return
    setView(id)
  }

  function handleComplete(data: any) {
    setResult(data)
    setAnalyzed(true)
    // Auto-advance to View 02 upon successful pipeline completion
    setView("analysis")
  }

  function handleReset() {
    setResult(null)
    setAnalyzed(false)
    setView("ingestion")
  }

  return (
    <div className="flex h-screen overflow-hidden bg-background text-foreground">
      {/* Navigation Sidebar */}
      <Sidebar
        active={view}
        onNavigate={handleNavigate}
        analyzed={analyzed}
      />

      {/* Main Terminal Viewport */}
      <main className="relative flex-1 overflow-y-auto">
        <div className="spectre-grid-bg pointer-events-none absolute inset-0 opacity-30" />
        <div className="relative mx-auto w-full max-w-7xl px-6 py-8 lg:px-10">
          {/* View 01: Ingestion & Live Pipeline Execution */}
          {view === "ingestion" && (
            <IngestionHub onComplete={handleComplete} />
          )}

          {/* View 02: Advanced Analysis Terminal */}
          {view === "analysis" && analyzed && (
            <AnalysisTerminal result={result} />
          )}

          {/* View 03: GenAI Intelligence Suite & RBI Section 7.4 Reporting */}
          {view === "genai" && analyzed && (
            <GenAiSuite result={result} />
          )}
        </div>
      </main>
    </div>
  )
}