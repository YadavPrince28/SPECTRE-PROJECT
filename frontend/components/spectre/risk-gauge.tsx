"use client"

import { useEffect, useState } from "react"

export function getRiskBand(score: number, isOfficialBank = false, verdict?: string) {
  const clamped = Math.max(0, Math.min(100, Number.isFinite(score) ? score : 0))
  const effectiveScore = isOfficialBank ? Math.min(15, clamped) : clamped
  const upperVerdict = String(verdict ?? "").toUpperCase()

  if (isOfficialBank || upperVerdict === "LOW" || effectiveScore <= 30) {
    return {
      tier: "LOW" as const,
      label: "LOW",
      color: "#10b981",
      score: effectiveScore,
    }
  }
  if (upperVerdict === "MODERATE" || upperVerdict === "MEDIUM" || effectiveScore <= 60) {
    return {
      tier: "MODERATE" as const,
      label: "MODERATE",
      color: "#f59e0b",
      score: effectiveScore,
    }
  }
  if (upperVerdict === "HIGH" || effectiveScore <= 80) {
    return {
      tier: "HIGH" as const,
      label: "HIGH",
      color: "#f97316",
      score: effectiveScore,
    }
  }
  return {
    tier: "CRITICAL" as const,
    label: "CRITICAL",
    color: "#f43f5e",
    score: effectiveScore,
  }
}

export function RiskGauge({
  value = 94,
  verdict,
  isOfficialBank = false,
}: {
  value?: number
  verdict?: string
  isOfficialBank?: boolean
}) {
  const band = getRiskBand(value, isOfficialBank, verdict)
  const targetValue = Math.round(band.score)
  const [animated, setAnimated] = useState(0)

  useEffect(() => {
    const t = setTimeout(() => setAnimated(targetValue), 150)
    return () => clearTimeout(t)
  }, [targetValue])

  const radius = 80
  const fullCircle = 2 * Math.PI * radius
  const dash = (Math.max(0, Math.min(100, animated)) / 100) * fullCircle

  return (
    <div className="relative flex flex-col items-center justify-center">
      <svg width="200" height="200" viewBox="0 0 200 200" className="-rotate-90">
        <circle
          cx="100"
          cy="100"
          r={radius}
          fill="none"
          stroke="rgba(148,163,184,0.12)"
          strokeWidth="14"
        />
        <circle
          cx="100"
          cy="100"
          r={radius}
          fill="none"
          stroke={band.color}
          strokeWidth="14"
          strokeLinecap="round"
          strokeDasharray={`${dash} ${fullCircle}`}
          style={{
            transition: "stroke-dasharray 1.1s cubic-bezier(0.22,1,0.36,1), stroke 0.3s ease",
            filter: `drop-shadow(0 0 8px ${band.color})`,
          }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span
          className="font-mono text-4xl font-bold tabular-nums"
          style={{ color: band.color }}
        >
          {Math.round(animated)}
        </span>
        <span className="font-mono text-[10px] tracking-widest text-slate-500">/ 100</span>
        <span
          className="mt-1 rounded px-2 py-0.5 font-mono text-[10px] font-bold tracking-wider"
          style={{ color: band.color, backgroundColor: `${band.color}1a` }}
        >
          {band.label}
        </span>
      </div>
    </div>
  )
}