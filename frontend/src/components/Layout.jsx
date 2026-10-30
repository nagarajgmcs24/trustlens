import { Link, NavLink } from 'react-router-dom'
import { ShieldCheck, AlertTriangle, Home, BarChart3, BookOpen } from 'lucide-react'

const navItems = [
  { to: '/', label: 'Home', icon: Home },
  { to: '/dashboard', label: 'Dashboard', icon: BarChart3 },
  { to: '/analyze', label: 'Analyze', icon: AlertTriangle },
  { to: '/about', label: 'About', icon: BookOpen },
]

export default function Layout({ children }) {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="sticky top-0 z-20 border-b border-white/10 bg-slate-950/80 backdrop-blur-xl">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-4 sm:px-6 lg:px-8">
          <Link to="/" className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-violet-500 to-cyan-400 shadow-lg shadow-violet-500/30">
              <ShieldCheck className="h-5 w-5 text-white" />
            </div>
            <div>
              <div className="text-lg font-semibold tracking-wide text-white">TRUSTLENS</div>
              <div className="text-[10px] uppercase tracking-[0.25em] text-slate-400">Cyber Risk Lens</div>
            </div>
          </Link>

          <nav className="flex w-full items-center justify-center gap-1 overflow-x-auto md:w-auto md:gap-2">
            {navItems.map(({ to, label, icon: Icon }) => (
              <NavLink
                key={to}
                to={to}
                className={({ isActive }) =>
                  `flex shrink-0 items-center gap-1 rounded-full px-2 py-2 text-xs transition sm:gap-2 sm:px-3 sm:text-sm ${
                    isActive ? 'bg-violet-500/20 text-violet-200 ring-1 ring-violet-500/40' : 'text-slate-300 hover:bg-white/5 hover:text-white'
                  }`
                }
              >
                <Icon className="h-4 w-4" />
                {label}
              </NavLink>
            ))}
          </nav>
        </div>
      </header>

      <main>{children}</main>
    </div>
  )
}
