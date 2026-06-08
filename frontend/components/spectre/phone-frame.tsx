"use client"

import { Fingerprint, Lock, ShieldAlert } from "lucide-react"
import type { StoryboardScreen } from "@/lib/spectre-data"

export function PhoneFrame({ screen }: { screen: StoryboardScreen["device"] }) {
  return (
    <div className="relative mx-auto h-[460px] w-[230px] rounded-[2.2rem] border-[6px] border-slate-700 bg-slate-950 p-2 shadow-[0_0_40px_-10px] shadow-cyan-400/20">
      {/* notch */}
      <div className="absolute left-1/2 top-2 z-10 h-5 w-24 -translate-x-1/2 rounded-full bg-slate-800" />
      {/* screen */}
      <div className="relative flex h-full w-full flex-col overflow-hidden rounded-[1.7rem] bg-gradient-to-b from-slate-900 to-slate-950">
        {/* fake status bar */}
        <div className="flex items-center justify-between px-4 pt-3 font-mono text-[9px] text-slate-500">
          <span>9:41</span>
          <span>5G · 84%</span>
        </div>

        <ScreenBody screen={screen} />
      </div>
    </div>
  )
}

function ScreenBody({ screen }: { screen: StoryboardScreen["device"] }) {
  if (screen.variant === "splash") {
    return (
      <div className="flex flex-1 flex-col items-center justify-center gap-4 px-6 text-center">
        <div className="flex size-16 items-center justify-center rounded-2xl border border-cyan-400/30 bg-cyan-400/10">
          <Lock className="size-8 text-cyan-400" />
        </div>
        <h3 className="text-sm font-bold text-slate-100">{screen.bankName}</h3>
        <p className="text-xs font-medium text-slate-300">{screen.headline}</p>
        <p className="text-[10px] leading-relaxed text-slate-500">{screen.body}</p>
        <div className="mt-2 h-1 w-24 overflow-hidden rounded-full bg-slate-800">
          <div className="h-full w-2/3 rounded-full bg-cyan-400" />
        </div>
      </div>
    )
  }

  if (screen.variant === "modal") {
    return (
      <div className="flex flex-1 flex-col items-center justify-center px-4">
        <div className="w-full rounded-xl border border-rose-500/40 bg-slate-900 p-4 text-center shadow-[0_0_24px_-6px] shadow-rose-500/40">
          <div className="mx-auto mb-3 flex size-11 items-center justify-center rounded-full bg-rose-500/15">
            <ShieldAlert className="size-6 text-rose-400" />
          </div>
          <h3 className="text-sm font-bold text-rose-400">{screen.headline}</h3>
          <p className="mt-2 text-[10px] leading-relaxed text-slate-400">{screen.body}</p>
          <button className="mt-4 w-full rounded-lg bg-rose-500 py-2 text-xs font-bold text-white">
            Verify Now
          </button>
          <p className="mt-2 font-mono text-[9px] text-rose-400">⏱ 09:58 remaining</p>
        </div>
      </div>
    )
  }

  if (screen.variant === "credentials") {
    return (
      <div className="flex flex-1 flex-col gap-3 px-5 pt-4">
        <div className="flex items-center gap-2">
          <Lock className="size-4 text-cyan-400" />
          <h3 className="text-sm font-bold text-slate-100">{screen.headline}</h3>
        </div>
        <p className="text-[10px] leading-relaxed text-slate-500">{screen.body}</p>
        <Field label="Customer ID" value="••••••••" />
        <Field label="MPIN" value="••••" />
        <button className="mt-1 w-full rounded-lg bg-cyan-400 py-2 text-xs font-bold text-slate-950">
          Restore Access
        </button>
        <div className="mt-auto mb-4 flex items-center gap-1.5 text-[9px] text-slate-600">
          <Fingerprint className="size-3" /> Secured by UnionTrust 256-bit
        </div>
      </div>
    )
  }

  // otp
  return (
    <div className="flex flex-1 flex-col gap-4 px-5 pt-6">
      <h3 className="text-sm font-bold text-slate-100">{screen.headline}</h3>
      <p className="text-[10px] leading-relaxed text-slate-500">{screen.body}</p>
      <div className="flex justify-center gap-2">
        {["8", "4", "7", "2", "9", "1"].map((d, i) => (
          <div
            key={i}
            className="flex size-7 items-center justify-center rounded-md border border-cyan-400/40 bg-slate-900 font-mono text-sm font-bold text-cyan-400"
          >
            {d}
          </div>
        ))}
      </div>
      <button className="mt-1 w-full rounded-lg bg-cyan-400 py-2 text-xs font-bold text-slate-950">
        Confirm OTP
      </button>
      <p className="text-center font-mono text-[9px] text-rose-400">
        ⚠ OTP forwarded to C2 before display
      </p>
    </div>
  )
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="space-y-1">
      <span className="font-mono text-[9px] uppercase tracking-wider text-slate-500">{label}</span>
      <div className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 font-mono text-sm text-slate-300">
        {value}
      </div>
    </div>
  )
}
