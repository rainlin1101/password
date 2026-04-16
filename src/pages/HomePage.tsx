import { useMemo } from 'react'
import { Link } from 'react-router-dom'
import questions from '../data/questions.json'
import { AppHeader } from '../components/AppHeader'
import { loadLastScore } from '../utils/storage'

export const HomePage = () => {
  const lastScore = useMemo(() => loadLastScore(), [])

  return (
    <div className="space-y-4">
      <AppHeader title="航空用语略称练习" subtitle="日语 → 英文略称" />

      <section className="rounded-3xl bg-gradient-to-r from-brand-500 to-cyan-400 p-5 text-white shadow-card">
        <p className="text-sm opacity-90">轻量刷题模式</p>
        <h2 className="mt-1 text-2xl font-bold">开始今天的练习</h2>
        <p className="mt-2 text-sm opacity-90">共 {questions.length} 题，随机打乱，手机优先体验。</p>
      </section>

      <div className="grid gap-3">
        <Link to="/quiz?mode=all" className="rounded-2xl bg-brand-600 px-4 py-4 text-center text-lg font-bold text-white active:scale-[0.99]">
          开始刷题
        </Link>
        <Link to="/category" className="rounded-2xl bg-white px-4 py-4 text-center text-base font-semibold text-slate-700 shadow-card">
          分类练习
        </Link>
        <Link to="/wrong-book" className="rounded-2xl bg-white px-4 py-4 text-center text-base font-semibold text-slate-700 shadow-card">
          错题本
        </Link>
      </div>

      {lastScore ? (
        <section className="rounded-3xl bg-white p-4 shadow-card">
          <p className="text-sm text-slate-500">最近成绩</p>
          <div className="mt-2 flex items-end justify-between">
            <p className="text-3xl font-extrabold text-brand-600">{lastScore.accuracy}%</p>
            <p className="text-sm text-slate-500">
              {lastScore.correct} / {lastScore.total}
            </p>
          </div>
        </section>
      ) : null}
    </div>
  )
}
