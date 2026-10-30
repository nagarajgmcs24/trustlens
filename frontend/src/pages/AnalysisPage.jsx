import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { AlertTriangle, Eraser, LoaderCircle, ShieldCheck } from 'lucide-react'
import { analyzeMessage } from '../services/api'

const CHANNELS = ['SMS', 'Email', 'WhatsApp', 'Other']
const LANGUAGES = ['English', 'Hindi', 'Kannada']

export default function AnalysisPage() {
  const navigate = useNavigate()
  const [message, setMessage] = useState('')
  const [channel, setChannel] = useState('SMS')
  const [language, setLanguage] = useState('English')
  const [senderName, setSenderName] = useState('')
  const [claimedOrganization, setClaimedOrganization] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [error, setError] = useState('')

  async function handleSubmit(event) {
    event.preventDefault()

    const cleanedMessage = message.trim()
    if (!cleanedMessage) {
      setError('Please enter a message before analyzing.')
      return
    }

    setError('')
    setIsSubmitting(true)

    try {
      const result = await analyzeMessage({
        message: cleanedMessage,
        channel,
        language,
        sender_name: senderName.trim() && !senderName.includes('@') ? senderName.trim() : undefined,
        sender_email: senderName.includes('@') ? senderName.trim() : undefined,
        claimed_organization: claimedOrganization.trim() || undefined,
      })

      const history = JSON.parse(localStorage.getItem('trustlensHistory') || '[]')
      const nextHistory = [
        ...history,
        {
          analysis_id: result.analysis_id,
          timestamp: result.timestamp,
          channel: result.channel,
          risk_level: result.effective_risk_level || result.risk_level,
          risk_score: result.effective_risk_score ?? result.context_score ?? result.risk_score,
          detected_categories: result.detected_categories,
        },
      ]
      localStorage.setItem('trustlensHistory', JSON.stringify(nextHistory))
      localStorage.setItem('latestAnalysis', JSON.stringify(result))

      navigate('/results', { state: { analysis: result, originalMessage: cleanedMessage } })
    } catch (requestError) {
      setError(requestError?.response?.data?.detail || 'The backend could not analyze this message. Please try again.')
    } finally {
      setIsSubmitting(false)
    }
  }

  function clearForm() {
    setMessage('')
    setSenderName('')
    setClaimedOrganization('')
    setError('')
  }

  return (
    <div className="mx-auto max-w-5xl px-4 py-10 sm:px-6 lg:px-8">
      <div className="mb-8 flex items-center gap-3">
        <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-violet-500/15 text-violet-300">
          <AlertTriangle className="h-5 w-5" />
        </div>
        <div>
          <p className="text-sm uppercase tracking-[0.2em] text-violet-300">Message analysis</p>
          <h1 className="text-3xl font-bold text-white">Check for phishing and impersonation indicators</h1>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="rounded-3xl border border-white/10 bg-slate-900/70 p-6">
        <div className="grid gap-6 lg:grid-cols-[1.2fr_0.8fr]">
          <div>
            <label htmlFor="message" className="mb-2 block text-sm font-medium text-slate-200">
              Suspicious message
            </label>
            <textarea
              id="message"
              value={message}
              onChange={(event) => setMessage(event.target.value)}
              rows={13}
              placeholder="Paste the message you want to review here..."
              className="w-full rounded-2xl border border-white/10 bg-slate-950/60 p-4 text-slate-100 outline-none transition focus:border-violet-500 focus:ring-2 focus:ring-violet-500/20"
            />
          </div>

          <div className="space-y-5">
            <div>
              <label className="mb-2 block text-sm font-medium text-slate-200">Message source</label>
              <div className="grid grid-cols-2 gap-2">
                {CHANNELS.map((option) => (
                  <button
                    key={option}
                    type="button"
                    aria-pressed={channel === option}
                    onClick={() => setChannel(option)}
                    className={`rounded-xl border px-3 py-2 text-sm font-medium transition ${
                      channel === option
                        ? 'border-violet-400 bg-violet-500/15 text-violet-200'
                        : 'border-white/10 bg-slate-950/50 text-slate-300 hover:border-violet-500/30'
                    }`}
                  >
                    {option}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label htmlFor="language" className="mb-2 block text-sm font-medium text-slate-200">
                Message language
              </label>
              <select
                id="language"
                value={language}
                onChange={(event) => setLanguage(event.target.value)}
                className="w-full rounded-xl border border-white/10 bg-slate-950/60 p-3 text-slate-100 outline-none transition focus:border-violet-500 focus:ring-2 focus:ring-violet-500/20"
              >
                {LANGUAGES.map((option) => <option key={option} value={option}>{option}</option>)}
              </select>
              {language !== 'English' && (
                <p className="mt-2 text-sm text-amber-200">
                  {language} phrase checks have limited coverage. Results may miss scams or misunderstand context; suspicious URL patterns are also checked.
                </p>
              )}
            </div>

            <div>
              <label htmlFor="claimedOrganization" className="mb-2 block text-sm font-medium text-slate-200">
                Organization claimed in message (optional)
              </label>
              <input
                id="claimedOrganization"
                value={claimedOrganization}
                onChange={(event) => setClaimedOrganization(event.target.value)}
                placeholder="e.g. HDFC Bank or UIDAI"
                maxLength={120}
                className="w-full rounded-xl border border-white/10 bg-slate-950/60 p-3 text-slate-100 outline-none transition focus:border-violet-500 focus:ring-2 focus:ring-violet-500/20"
              />
            </div>

            <div>
              <label htmlFor="senderName" className="mb-2 block text-sm font-medium text-slate-200">
                Sender name or email address (optional)
              </label>
              <input
                id="senderName"
                value={senderName}
                onChange={(event) => setSenderName(event.target.value)}
                placeholder="e.g. ICICI Bank Support or support@fakebank.co"
                maxLength={200}
                className="w-full rounded-xl border border-white/10 bg-slate-950/60 p-3 text-slate-100 outline-none transition focus:border-violet-500 focus:ring-2 focus:ring-violet-500/20"
              />
            </div>

            <div className="rounded-2xl border border-amber-500/20 bg-amber-500/5 p-4 text-sm text-amber-100">
              This is an automated risk assessment, not a confirmed fraud determination.
            </div>

            {error && <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-200">{error}</div>}

            <div className="flex flex-wrap gap-3 pt-2">
              <button
                type="submit"
                disabled={isSubmitting}
                className="inline-flex items-center justify-center gap-2 rounded-full bg-violet-500 px-5 py-3 font-medium text-white shadow-lg shadow-violet-500/20 transition hover:bg-violet-400 disabled:cursor-not-allowed disabled:opacity-70"
              >
                {isSubmitting ? <LoaderCircle className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
                {isSubmitting ? 'Analyzing...' : 'Analyze Message'}
              </button>

              <button
                type="button"
                onClick={clearForm}
                className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-slate-950 px-5 py-3 font-medium text-slate-200 hover:bg-white/5"
              >
                <Eraser className="h-4 w-4" />
                Clear
              </button>
            </div>
          </div>
        </div>
      </form>
    </div>
  )
}
