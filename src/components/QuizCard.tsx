import type { Question } from '../types/question'

type Props = {
  question: Question
}

export const QuizCard = ({ question }: Props) => {
  return (
    <section className="rounded-3xl bg-white p-6 shadow-card">
      <p className="mb-3 inline-block rounded-full bg-brand-50 px-3 py-1 text-xs font-semibold text-brand-600">
        {question.category}
      </p>
      <p className="text-xs text-slate-500">请输入对应的英文略称</p>
      <h2 className="mt-3 text-3xl font-bold leading-tight text-slate-900">{question.japanese}</h2>
    </section>
  )
}
