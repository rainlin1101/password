import { FormEvent, useEffect, useMemo, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import questions from '../data/questions.json'
import { AppHeader } from '../components/AppHeader'
import { BottomActionBar } from '../components/BottomActionBar'
import { ProgressBar } from '../components/ProgressBar'
import { QuizCard } from '../components/QuizCard'
import type { Question, QuizResult } from '../types/question'
import { isAnswerCorrect, shuffleQuestions } from '../utils/quiz'
import {
  addWrongQuestion,
  clearSessionQuestions,
  loadWrongBook,
  saveLastScore,
  saveSessionQuestions,
  saveSessionResult,
} from '../utils/storage'

export const QuizPage = () => {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const mode = searchParams.get('mode') ?? 'all'
  const selectedCategory = searchParams.get('category') ?? ''

  const quizQuestions = useMemo(() => {
    const all = questions as Question[]
    if (mode === 'wrong') {
      return shuffleQuestions(loadWrongBook())
    }
    if (mode === 'category') {
      return shuffleQuestions(all.filter((item) => item.category === selectedCategory))
    }
    return shuffleQuestions(all)
  }, [mode, selectedCategory])

  const [index, setIndex] = useState(0)
  const [input, setInput] = useState('')
  const [submitted, setSubmitted] = useState(false)
  const [correctCount, setCorrectCount] = useState(0)
  const [feedback, setFeedback] = useState<'correct' | 'wrong' | null>(null)

  const current = quizQuestions[index]

  useEffect(() => {
    if (quizQuestions.length === 0) return
    saveSessionQuestions(quizQuestions.map((q) => q.id))
  }, [quizQuestions])

  useEffect(() => {
    if (quizQuestions.length === 0) {
      navigate('/result', { replace: true })
    }
  }, [navigate, quizQuestions.length])

  const submit = (event?: FormEvent) => {
    event?.preventDefault()
    if (!current || submitted) return
    const ok = isAnswerCorrect(input, current.abbreviation)
    setSubmitted(true)
    setFeedback(ok ? 'correct' : 'wrong')
    if (ok) {
      setCorrectCount((prev) => prev + 1)
    } else {
      addWrongQuestion(current)
    }
  }

  const nextQuestion = () => {
    if (!current) return
    if (index + 1 >= quizQuestions.length) {
      const total = quizQuestions.length
      const correct = correctCount
      const wrong = total - correct
      const result: QuizResult = {
        total,
        correct,
        wrong,
        accuracy: total === 0 ? 0 : Math.round((correct / total) * 100),
        mode: mode === 'category' ? 'category' : mode === 'wrong' ? 'wrong' : 'all',
        category: selectedCategory || undefined,
        finishedAt: new Date().toISOString(),
      }
      saveLastScore(result)
      saveSessionResult(result)
      clearSessionQuestions()
      navigate('/result')
      return
    }
    setIndex((prev) => prev + 1)
    setInput('')
    setSubmitted(false)
    setFeedback(null)
  }

  if (!current) return null

  return (
    <div className="space-y-4">
      <AppHeader title="刷题中" subtitle="日语 → 英文略称" showHome />
      <ProgressBar current={index + 1} total={quizQuestions.length} />
      <QuizCard question={current} />

      <form onSubmit={submit} className="space-y-3">
        <input
          autoFocus
          value={input}
          onChange={(event) => setInput(event.target.value)}
          placeholder="输入 abbreviation，例如 ETA"
          className="h-14 w-full rounded-2xl border border-slate-200 bg-white px-4 text-lg font-semibold uppercase tracking-wide text-slate-900 shadow-card outline-none ring-brand-200 focus:ring"
        />
        {!submitted ? (
          <button type="submit" className="w-full rounded-2xl bg-brand-600 py-3 text-lg font-bold text-white active:scale-[0.99]">
            提交
          </button>
        ) : null}
      </form>

      {submitted ? (
        <section
          className={`rounded-2xl p-4 text-sm shadow-card ${
            feedback === 'correct' ? 'bg-emerald-50 text-emerald-700' : 'bg-rose-50 text-rose-700'
          }`}
        >
          <p className="text-base font-bold">{feedback === 'correct' ? '答对了！' : '答错了，再记一遍！'}</p>
          <p className="mt-1">正确答案：{current.abbreviation}</p>
          <p>英文全称：{current.english}</p>
        </section>
      ) : null}

      {submitted ? (
        <BottomActionBar>
          <button onClick={nextQuestion} className="w-full rounded-2xl bg-slate-900 py-3 text-base font-bold text-white">
            下一题
          </button>
        </BottomActionBar>
      ) : null}
    </div>
  )
}
