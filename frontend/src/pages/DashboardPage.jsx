import { useEffect, useMemo, useState } from 'react'
import { ArrowRight, BarChart3, ShieldAlert, History, ShieldCheck, Sparkles } from 'lucide-react'
import { Link } from 'react-router-dom'
import { getHistory } from '../services/api'

function loadHistory() {
  try {
    const raw = localStorage.getItem('trustlensHistory')
    return raw ? JSON.parse(raw) : []
  } catch {
    return []
  }
}

export default function DashboardPage() {
  const [history, setHistory] = useState([])
  const [historySource, setHistorySource] = useState('loading')

  useEffect(() => {
    let active = true

    getHistory()
      .then((records) => {
        if (!active) return
        setHistory(records)
        setHistorySource('api')
      })
      .catch(() => {
        if (!active) return
        setHistory(loadHistory().slice().reverse())
        setHistorySource('local')
      })

    return () => {
      active = false
    }
  }, [])

  const stats = useMemo(() => {
    const total = history.length
    const high = history.filter((item) => item.risk_level === 'HIGH RISK').length
    const medium = history.filter((item) => item.risk_level === 'MEDIUM RISK').length
    const low = history.filter((item) => item.risk_level === 'LOW RISK').length

    return { total, high, medium, low }
  }, [history])

  const recent = history.slice(0, 5)

  return (
    <div className="mx-auto max-w-7xl px-4 py-10 sm:px-6 lg:px-8">
      <section className="mb-10 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="text-sm uppercase tracking-[0.2em] text-violet-300">Dashboard</p>
          <h1 className="mt-2 text-3xl font-bold text-white">Welcome back</h1>
        </div>
        <Link to="/analyze" className="inline-flex items-center gap-2 rounded-full bg-violet-500 px-4 py-2.5 font-medium text-white shadow-lg shadow-violet-500/20 hover:bg-violet-400">
          Quick Analyze
          <ArrowRight className="h-4 w-4" />
        </Link>
      </section>

      <section className="grid gap-5 md:grid-cols-4">
        <StatCard title="Analyses in history (latest 100)" value={stats.total} icon={BarChart3} accent="text-violet-300" />
        <StatCard title="High-risk" value={stats.high} icon={ShieldAlert} accent="text-red-300" />
        <StatCard title="Medium-risk" value={stats.medium} icon={Sparkles} accent="text-amber-300" />
        <StatCard title="Low-risk" value={stats.low} icon={ShieldCheck} accent="text-emerald-300" />
      </section>

      <section className="mt-10 grid gap-8 lg:grid-cols-[1.3fr_0.7fr]">
        <div className="rounded-3xl border border-white/10 bg-slate-900/70 p-6">
          <div className="mb-4 flex items-center gap-3">
            <History className="h-5 w-5 text-violet-300" />
            <h2 className="text-xl font-semibold text-white">Recent analysis history</h2>
          </div>

          {historySource === 'loading' ? (
            <div className="rounded-2xl border border-white/10 bg-slate-950/40 p-6 text-slate-300">
              Loading saved analysis history...
            </div>
          ) : recent.length === 0 ? (
            <div className="rounded-2xl border border-dashed border-white/10 bg-slate-950/40 p-6 text-slate-300">
              No saved analysis yet. Start with a quick risk scan to populate the dashboard.
            </div>
          ) : (
            <>
              {historySource === 'local' && (
                <p className="mb-3 text-xs text-amber-200">API unavailable; showing browser-only history.</p>
              )}
              <div className="space-y-3">
                {recent.map((item) => (
                  <div key={item.analysis_id} className="flex items-center justify-between gap-4 rounded-2xl border border-white/10 bg-slate-950/40 p-4">
                    <div>
                      <div className="font-medium text-white">{item.channel}</div>
                      <div className="text-sm text-slate-400">{new Date(item.timestamp).toLocaleString()}</div>
                      <div className="mt-1 text-xs text-slate-500">Score: {item.risk_score}/100</div>
                    </div>
                    <span className={`rounded-full px-2.5 py-1 text-xs font-semibold ${getRiskTone(item.risk_level)}`}>
                      {item.risk_level}
                    </span>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>

        <div className="rounded-3xl border border-violet-500/20 bg-gradient-to-br from-violet-500/10 via-slate-900 to-cyan-500/10 p-6">
          <h3 className="text-lg font-semibold text-white">Risk summary</h3>
          <p className="mt-3 text-slate-300">
            {history.length === 0
              ? 'Your analysis data will appear here after the first scan.'
              : `Latest assessment indicates ${history[0].risk_level.toLowerCase()} for recent messages.`}
          </p>
          <div className="mt-5 rounded-2xl border border-white/10 bg-slate-950/40 p-4">
            <div className="text-xs uppercase tracking-[0.2em] text-slate-400">Current status</div>
            <div className="mt-2 text-2xl font-bold text-white">
              {history.length === 0 ? 'Awaiting scan' : history[0].risk_level}
            </div>
          </div>
        </div>
      </section>
    </div>
  )
}

function StatCard({ title, value, icon: Icon, accent }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-slate-900/70 p-5 shadow-lg shadow-slate-950/25">
      <div className="flex items-center justify-between">
        <p className="text-sm text-slate-300">{title}</p>
        <div className={`rounded-xl bg-white/5 p-2 ${accent}`}>
          <Icon className="h-4 w-4" />
        </div>
      </div>
      <div className="mt-4 text-3xl font-bold text-white">{value}</div>
    </div>
  )
}

function getRiskTone(level) {
  if (level === 'HIGH RISK') return 'bg-red-500/15 text-red-300'
  if (level === 'MEDIUM RISK') return 'bg-amber-500/15 text-amber-300'
  return 'bg-emerald-500/15 text-emerald-300'
}
