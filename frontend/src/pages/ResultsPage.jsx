import { useLocation, useNavigate } from 'react-router-dom'
import { ArrowLeft, CheckCircle2, AlertTriangle, ExternalLink, ShieldAlert } from 'lucide-react'

const riskColors = {
  'LOW RISK': 'bg-emerald-500/15 text-emerald-200 border-emerald-500/30',
  'MEDIUM RISK': 'bg-amber-500/15 text-amber-200 border-amber-500/30',
  'HIGH RISK': 'bg-red-500/15 text-red-200 border-red-500/30',
}

export default function ResultsPage() {
  const navigate = useNavigate()
  const { state } = useLocation()
  const originalMessage = state?.originalMessage

  let analysis = state?.analysis
  if (!analysis) {
    try {
      analysis = JSON.parse(localStorage.getItem('latestAnalysis') || 'null')
    } catch {
      analysis = null
    }
  }

  if (!analysis) {
    return (
      <div className="mx-auto max-w-3xl px-4 py-20 text-center">
        <ShieldAlert className="mx-auto mb-4 h-14 w-14 text-amber-300" />
        <h1 className="text-3xl font-bold text-white">No analysis found</h1>
        <p className="mt-4 text-slate-300">Please run a new scan before opening the results page.</p>
        <button onClick={() => navigate('/analyze')} className="mt-6 rounded-full bg-violet-500 px-5 py-3 text-white">Go to analyzer</button>
      </div>
    )
  }

  return (
    <div className="mx-auto max-w-6xl px-4 py-10 sm:px-6 lg:px-8">
      <button onClick={() => navigate('/analyze')} className="mb-6 inline-flex items-center gap-2 text-sm text-slate-300 hover:text-white">
        <ArrowLeft className="h-4 w-4" />
        Back to analyser
      </button>

      <section className="rounded-3xl border border-white/10 bg-slate-900/80 p-6 shadow-2xl shadow-slate-950/30">
        <div className="flex flex-col gap-5 md:flex-row md:items-center md:justify-between">
          <div>
            <p className="text-sm uppercase tracking-[0.2em] text-violet-300">Risk report</p>
            <h1 className="mt-2 text-3xl font-bold text-white">{analysis.risk_level}</h1>
          </div>
          <div className={`inline-flex items-center gap-2 rounded-full border px-4 py-2 text-sm font-semibold ${riskColors[analysis.risk_level]}`}>
            {analysis.risk_level === 'HIGH RISK' ? <AlertTriangle className="h-4 w-4" /> : <CheckCircle2 className="h-4 w-4" />}
            {analysis.risk_score}/100
          </div>
        </div>

        <div className="mt-6 grid gap-5 md:grid-cols-3">
          <MetricCard label="Score" value={`${analysis.risk_score}/100`} color="text-violet-300" />
          <MetricCard label="Category" value={analysis.risk_level} color="text-cyan-300" />
          <MetricCard label="Threat groups" value={analysis.detected_categories.length || 'None'} color="text-amber-300" />
        </div>
        <div className="mt-5 flex flex-wrap gap-3 text-sm text-slate-300">
          <span className="rounded-full border border-white/10 bg-slate-950/50 px-3 py-1">Source: {analysis.channel || 'Other'}</span>
          <span className="rounded-full border border-white/10 bg-slate-950/50 px-3 py-1">Language: {analysis.language || 'English'}</span>
        </div>
        {analysis.language_support && (
          <p className={`mt-4 rounded-xl border p-3 text-sm ${
            analysis.language === 'English'
              ? 'border-slate-700 bg-slate-950/40 text-slate-300'
              : 'border-amber-500/20 bg-amber-500/5 text-amber-100'
          }`}>
            {analysis.language_support}
          </p>
        )}
      </section>

      <section className="mt-8 grid gap-8 lg:grid-cols-[1.2fr_0.8fr]">
        <div className="space-y-8">
          <Panel title="Why this was flagged">
            <ul className="space-y-3 text-slate-300">
              {analysis.explanations.map((item) => (
                <li key={item} className="flex gap-3 rounded-xl border border-white/10 bg-slate-900/40 p-3">
                  <span className="mt-1 text-violet-300">•</span>
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </Panel>

          <Panel title="Detected threat categories">
            <div className="flex flex-wrap gap-2">
              {analysis.detected_categories.length ? analysis.detected_categories.map((category) => (
                <span key={category} className="rounded-full border border-violet-500/30 bg-violet-500/10 px-3 py-1 text-sm text-violet-200">
                  {category}
                </span>
              )) : <span className="text-slate-400">No strong category match identified.</span>}
            </div>
          </Panel>

          <Panel title="Evidence found">
            {analysis.evidence?.length ? (
              <ul className="space-y-3">
                {analysis.evidence.map((item, index) => (
                  <li key={`${item.category}-${index}`} className="rounded-xl border border-white/10 bg-slate-900/40 p-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="font-medium text-violet-200">{item.category}</span>
                      <span className="rounded-full bg-slate-800 px-2 py-1 text-xs text-slate-300">+{item.points_contributed ?? item.weight} points</span>
                    </div>
                    <p className="mt-2 text-sm text-slate-300">
                      Matched: <span className="font-medium text-white">{item.matched_phrase || item.reason}</span>
                    </p>
                    {item.language && (
                      <p className="mt-1 text-xs text-slate-400">Detected language: {item.language}</p>
                    )}
                    {item.explanation && <p className="mt-2 text-sm text-slate-300">{item.explanation}</p>}
                    {!item.explanation && item.reason && <p className="mt-2 text-sm text-slate-300">{item.reason}</p>}
                    {item.recommended_action && (
                      <p className="mt-2 text-sm text-emerald-200">Safe action: {item.recommended_action}</p>
                    )}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-slate-400">No specific risk evidence matched the current rules.</p>
            )}
          </Panel>

          <Panel title="Suspicious keywords">
            <div className="flex flex-wrap gap-2">
              {analysis.suspicious_keywords.length ? analysis.suspicious_keywords.map((keyword) => (
                <span key={keyword} className="rounded-full bg-slate-800 px-3 py-1 text-sm text-slate-200">
                  {keyword}
                </span>
              )) : <span className="text-slate-400">No obvious suspicious keywords matched.</span>}
            </div>
          </Panel>

          <Panel title="Suspicious URLs">
            {analysis.suspicious_urls.length ? (
              <ul className="space-y-2">
                {analysis.suspicious_urls.map((url) => (
                  <li key={url} className="flex items-center justify-between gap-3 rounded-xl border border-white/10 bg-slate-900/40 p-3 text-sm text-slate-300">
                    <span className="break-all">{url}</span>
                    <ExternalLink className="h-4 w-4 shrink-0 text-slate-400" />
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-slate-400">No suspicious URLs were identified in this message.</p>
            )}
          </Panel>
        </div>

        <div className="space-y-8">
          <Panel title="Recommended action">
            <ul className="space-y-3 text-slate-300">
              {analysis.recommendations.map((item) => (
                <li key={item} className="flex gap-3 rounded-xl border border-white/10 bg-slate-900/40 p-3">
                  <span className="mt-1 text-emerald-300">✓</span>
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </Panel>

          <Panel title="Original message">
            <div className="rounded-2xl border border-white/10 bg-slate-950/50 p-4 text-sm text-slate-300">
              {analysis.sender_name ? <p className="mb-2 text-violet-200">Sender: {analysis.sender_name}</p> : null}
              <p className="whitespace-pre-wrap">{originalMessage || 'Original message is not stored. Start a new analysis to review its contents.'}</p>
            </div>
          </Panel>
        </div>
      </section>
    </div>
  )
}

function Panel({ title, children }) {
  return (
    <div className="rounded-3xl border border-white/10 bg-slate-900/70 p-5">
      <h2 className="mb-4 text-xl font-semibold text-white">{title}</h2>
      {children}
    </div>
  )
}

function MetricCard({ label, value, color }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-slate-950/50 p-4">
      <div className="text-xs uppercase tracking-[0.2em] text-slate-400">{label}</div>
      <div className={`mt-3 text-2xl font-bold ${color}`}>{value}</div>
    </div>
  )
}
