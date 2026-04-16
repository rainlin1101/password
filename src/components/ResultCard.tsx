import type { QuizResult } from '../types/question'

type Props = {
  result: QuizResult
}

export const ResultCard = ({ result }: Props) => {
  return (
    <section className="rounded-3xl bg-white p-6 shadow-card">
      <p className="text-sm text-slate-500">本轮完成</p>
      <h2 className="mt-1 text-4xl font-extrabold text-brand-600">{result.accuracy}%</h2>
      <p className="text-sm text-slate-500">正确率</p>
      <div className="mt-5 grid grid-cols-2 gap-3 text-sm">
        <div className="rounded-2xl bg-slate-50 p-3">
          <p className="text-slate-500">总题数</p>
          <p className="text-lg font-bold text-slate-900">{result.total}</p>
        </div>
        <div className="rounded-2xl bg-emerald-50 p-3">
          <p className="text-emerald-600">正确</p>
          <p className="text-lg font-bold text-emerald-700">{result.correct}</p>
        </div>
        <div className="rounded-2xl bg-rose-50 p-3 col-span-2">
          <p className="text-rose-600">错误</p>
          <p className="text-lg font-bold text-rose-700">{result.wrong}</p>
        </div>
      </div>
    </section>
  )
}
