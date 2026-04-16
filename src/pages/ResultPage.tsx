import { Link } from 'react-router-dom'
import { AppHeader } from '../components/AppHeader'
import { ResultCard } from '../components/ResultCard'
import { loadLastScore, loadSessionResult } from '../utils/storage'

export const ResultPage = () => {
  const result = loadSessionResult() ?? loadLastScore()

  if (!result) {
    return (
      <div className="space-y-4">
        <AppHeader title="结果" showHome />
        <section className="rounded-2xl bg-white p-4 shadow-card">暂无成绩，先去刷题吧。</section>
        <Link to="/quiz?mode=all" className="block rounded-2xl bg-brand-600 py-3 text-center font-bold text-white">
          开始刷题
        </Link>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <AppHeader title="本轮结果" subtitle="继续保持" showHome />
      <ResultCard result={result} />
      <div className="grid gap-3">
        <Link to="/quiz?mode=all" className="rounded-2xl bg-brand-600 py-3 text-center text-base font-bold text-white">
          再来一轮
        </Link>
        <Link to="/wrong-book" className="rounded-2xl bg-white py-3 text-center text-base font-semibold text-slate-700 shadow-card">
          去错题本
        </Link>
        <Link to="/" className="rounded-2xl bg-white py-3 text-center text-base font-semibold text-slate-700 shadow-card">
          回首页
        </Link>
      </div>
    </div>
  )
}
