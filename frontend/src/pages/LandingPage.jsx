import { ArrowRight, Shield, ScanSearch, LockKeyhole, Network, MousePointerClick } from 'lucide-react'
import { Link } from 'react-router-dom'

const features = [
  { icon: ScanSearch, title: 'Behavioral detection', text: 'Flags urgency, manipulation, financial bait, fake government activity, and suspicious links.' },
  { icon: Shield, title: 'Privacy-first', text: 'The app checks messages locally and keeps only safe analysis metadata when persistence is enabled.' },
  { icon: LockKeyhole, title: 'Explainable scoring', text: 'Every alert is backed by a reason, a category, and clear guidance to verify the source.' },
]

const steps = [
  'Paste a suspicious message or sender detail into the analyzer.',
  'TRUSTLENS checks urgency, impersonation, URLs, and request patterns.',
  'Review the explanation, score, and recommended actions before taking any action.',
]

export default function LandingPage() {
  return (
    <div className="mx-auto max-w-7xl px-4 py-12 sm:px-6 lg:px-8">
      <section className="grid items-center gap-10 py-12 lg:grid-cols-[1.2fr_0.8fr]">
        <div>
          <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-violet-500/40 bg-violet-500/10 px-3 py-1 text-xs font-medium uppercase tracking-[0.22em] text-violet-200">
            Mitigate impersonation risk
          </div>
          <h1 className="max-w-xl text-4xl font-bold tracking-tight text-white sm:text-5xl lg:text-6xl">
            See Through the Scam. <span className="text-violet-300">Trust What Matters.</span>
          </h1>
          <p className="mt-6 max-w-xl text-lg text-slate-300">
            TRUSTLENS helps people spot suspicious phishing, impersonation, and social-engineering messages before they become a costly mistake.
          </p>

          <div className="mt-8 flex flex-wrap gap-4">
            <Link to="/analyze" className="inline-flex items-center gap-2 rounded-full bg-violet-500 px-5 py-3 font-medium text-white shadow-lg shadow-violet-500/30 transition hover:bg-violet-400">
              Start Analyzing
              <ArrowRight className="h-4 w-4" />
            </Link>
            <Link to="/dashboard" className="inline-flex items-center gap-2 rounded-full border border-white/15 px-5 py-3 font-medium text-slate-200 hover:bg-white/5">
              Dashboard
            </Link>
          </div>
        </div>

        <div className="rounded-3xl border border-violet-500/20 bg-gradient-to-br from-violet-500/15 via-slate-900 to-cyan-500/10 p-6 shadow-2xl shadow-violet-900/20">
          <div className="rounded-2xl border border-white/10 bg-slate-950/60 p-5">
            <div className="mb-4 flex items-center justify-between">
              <span className="text-sm font-medium text-violet-200">Analysis starts with your message</span>
              <span className="rounded-full bg-cyan-500/15 px-2 py-1 text-xs font-semibold text-cyan-200">READY</span>
            </div>
            <div className="rounded-2xl border border-dashed border-violet-500/30 bg-slate-900 p-4 text-sm text-slate-300">
              Your text is checked by the live TRUSTLENS backend. A risk score appears only after you submit a message for analysis.
            </div>
            <div className="mt-5 space-y-3 text-sm text-slate-300">
              <div className="flex items-center gap-3 rounded-xl bg-slate-800 p-3">
                <ScanSearch className="h-4 w-4 text-violet-300" />
                Rule-based analysis with clear explanations
              </div>
              <div className="flex items-center gap-3 rounded-xl bg-slate-800 p-3">
                <Shield className="h-4 w-4 text-cyan-300" />
                No links opened and no external AI service
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="mt-16">
        <div className="mb-8 text-center">
          <p className="text-sm uppercase tracking-[0.25em] text-violet-300">Features</p>
          <h2 className="mt-3 text-3xl font-bold text-white">Built to flag manipulative messaging</h2>
        </div>

        <div className="grid gap-6 md:grid-cols-3">
          {features.map(({ icon: Icon, title, text }) => (
            <div key={title} className="rounded-2xl border border-white/10 bg-slate-900/60 p-6 shadow-lg shadow-slate-950/30">
              <div className="mb-5 flex h-12 w-12 items-center justify-center rounded-xl bg-violet-500/15 text-violet-300">
                <Icon className="h-5 w-5" />
              </div>
              <h3 className="mb-2 text-xl font-semibold text-white">{title}</h3>
              <p className="text-slate-300">{text}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="mt-20 rounded-3xl border border-white/10 bg-slate-900/70 p-8">
        <div className="mb-8 text-center">
          <p className="text-sm uppercase tracking-[0.25em] text-cyan-300">How it works</p>
          <h2 className="mt-3 text-3xl font-bold text-white">A clear, explainable screening process</h2>
        </div>

        <div className="grid gap-6 md:grid-cols-3">
          {steps.map((step, index) => (
            <div key={step} className="rounded-2xl border border-white/10 bg-slate-950/40 p-5">
              <div className="mb-4 flex h-9 w-9 items-center justify-center rounded-full bg-cyan-500/15 text-sm font-bold text-cyan-300">
                {index + 1}
              </div>
              <p className="text-slate-300">{step}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="mt-20 grid gap-6 md:grid-cols-2">
        <div className="rounded-3xl border border-white/10 bg-slate-900/60 p-8">
          <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-xl bg-emerald-500/15 text-emerald-300">
            <MousePointerClick className="h-5 w-5" />
          </div>
          <h3 className="text-2xl font-bold text-white">Privacy-first design</h3>
          <p className="mt-3 text-slate-300">
            TRUSTLENS does not automatically click links and does not send your message to external AI services. The assessment is based on transparent heuristics and safe local analysis.
          </p>
        </div>

        <div className="rounded-3xl border border-white/10 bg-slate-900/60 p-8">
          <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-xl bg-amber-500/15 text-amber-300">
            <Network className="h-5 w-5" />
          </div>
          <h3 className="text-2xl font-bold text-white">Security-minded limits</h3>
          <p className="mt-3 text-slate-300">
            Automated detection is helpful, but it is not perfect. Important messages should still be checked independently using trusted channels and verified contacts.
          </p>
        </div>
      </section>
    </div>
  )
}
