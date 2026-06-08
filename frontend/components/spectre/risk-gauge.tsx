"use client"

import { useEffect, useState } from "react"

export function RiskGauge({ value = 94 }: { value?: number }) {
  const [animated, setAnimated] = useState(0)

  useEffect(() => {
    const t = setTimeout(() => setAnimated(value), 200)
    return () => clearTimeout(t)
  }, [value])

  const radius = 80
  const circumference = Math.PI * radius // semi would differ; using full circle minus gap
  const fullCircle = 2 * Math.PI * radius
  const dash = (animated / 100) * fullCircle

  // color by band
  const band =
    value <= 30
      ? { label: "LOW", color: "#10b981" }
      : value <= 60
        ? { label: "MODERATE", color: "#f59e0b" }
        : value <= 80
          ? { label: "HIGH", color: "#f97316" }
          : { label: "CRITICAL", color: "#f43f5e" }

  return (
    <div className="relative flex flex-col items-center justify-center">
      <svg width="200" height="200" viewBox="0 0 200 200" className="-rotate-90">
        <defs>
          <linearGradient id="gauge-grad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#10b981" />
            <stop offset="40%" stopColor="#f59e0b" />
            <stop offset="70%" stopColor="#f97316" />
            <stop offset="100%" stopColor="#f43f5e" />
          </linearGradient>
        </defs>
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
          stroke="url(#gauge-grad)"
          strokeWidth="14"
          strokeLinecap="round"
          strokeDasharray={`${dash} ${fullCircle}`}
          style={{
            transition: "stroke-dasharray 1.2s cubic-bezier(0.22,1,0.36,1)",
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
