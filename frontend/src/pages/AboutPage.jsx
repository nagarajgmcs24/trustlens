export default function AboutPage() {
  return (
    <div className="mx-auto max-w-5xl px-4 py-12 sm:px-6 lg:px-8">
      <div className="rounded-3xl border border-white/10 bg-slate-900/70 p-8">
        <p className="text-sm uppercase tracking-[0.25em] text-violet-300">About TRUSTLENS</p>
        <h1 className="mt-3 text-3xl font-bold text-white">A privacy-aware first line of defense against scams</h1>

        <div className="mt-8 space-y-6 text-slate-300">
          <p>
            TRUSTLENS is a cybersecurity-focused web application designed to help users spot suspicious messages involving phishing, impersonation, and social engineering. Instead of issuing a vague label, it explains the risk patterns it found and highlights why the message may be suspicious.
          </p>

          <p>
            Phishing and impersonation are dangerous because they exploit trust. A convincing message can pressure people into clicking links, sharing passwords, transferring money, or revealing personal information. These scams often rely on urgency, fear, or fake authority.
          </p>

          <p>
            The detection engine uses rule-based logic: it checks for urgency phrases, sensitive information requests, impersonation claims, suspicious links, and scam patterns such as government or bank impersonation. It scores the message and returns explanations so the user understands the result.
          </p>

          <p>
            Privacy is central to the design. TRUSTLENS avoids automatic URL visits and does not send user content to external AI systems. When MongoDB is configured, it stores only safe metadata such as timestamps, channel, risk level, score, and categories — not raw message content by default.
          </p>

          <p>
            The app is intentionally transparent about its limits. Automated heuristics are useful, but they are not foolproof. Important messages should always be verified through trusted contact channels, official websites, or known customer support numbers before any user action is taken.
          </p>
        </div>
      </div>
    </div>
  )
}
