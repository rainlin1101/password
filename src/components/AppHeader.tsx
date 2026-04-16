import { Link } from 'react-router-dom'

type Props = {
  title: string
  subtitle?: string
  showHome?: boolean
}

export const AppHeader = ({ title, subtitle, showHome = false }: Props) => {
  return (
    <header className="mb-4 rounded-3xl bg-white p-4 shadow-card">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-slate-800">{title}</h1>
          {subtitle ? <p className="mt-1 text-sm text-slate-500">{subtitle}</p> : null}
        </div>
        {showHome ? (
          <Link to="/" className="rounded-full bg-slate-100 px-3 py-1.5 text-xs font-semibold text-slate-600">
            首页
          </Link>
        ) : null}
      </div>
    </header>
  )
}
