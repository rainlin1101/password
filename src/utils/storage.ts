import type { Question, QuizResult } from '../types/question'

export const STORAGE_KEYS = {
  wrongBook: 'aviation_quiz_wrong_book',
  lastScore: 'aviation_quiz_last_score',
  settings: 'aviation_quiz_settings',
  recentCategory: 'aviation_quiz_recent_category',
  session: 'aviation_quiz_session',
  result: 'aviation_quiz_result',
} as const

const safeJsonParse = <T>(value: string | null, fallback: T): T => {
  if (!value) return fallback
  try {
    return JSON.parse(value) as T
  } catch {
    return fallback
  }
}

export const loadWrongBook = (): Question[] =>
  safeJsonParse<Question[]>(localStorage.getItem(STORAGE_KEYS.wrongBook), [])

export const saveWrongBook = (items: Question[]) => {
  localStorage.setItem(STORAGE_KEYS.wrongBook, JSON.stringify(items))
}

export const addWrongQuestion = (question: Question) => {
  const current = loadWrongBook()
  const existed = current.some((item) => item.id === question.id)
  const next = existed ? current : [question, ...current]
  saveWrongBook(next)
}

export const removeWrongQuestion = (id: number) => {
  const current = loadWrongBook()
  saveWrongBook(current.filter((item) => item.id !== id))
}

export const clearWrongBook = () => {
  saveWrongBook([])
}

export const saveLastScore = (result: QuizResult) => {
  localStorage.setItem(STORAGE_KEYS.lastScore, JSON.stringify(result))
}

export const loadLastScore = (): QuizResult | null =>
  safeJsonParse<QuizResult | null>(localStorage.getItem(STORAGE_KEYS.lastScore), null)

export const saveRecentCategory = (category: string) => {
  localStorage.setItem(STORAGE_KEYS.recentCategory, category)
}

export const loadRecentCategory = (): string => localStorage.getItem(STORAGE_KEYS.recentCategory) ?? ''

export const saveSessionQuestions = (ids: number[]) => {
  localStorage.setItem(STORAGE_KEYS.session, JSON.stringify(ids))
}

export const loadSessionQuestions = (): number[] =>
  safeJsonParse<number[]>(localStorage.getItem(STORAGE_KEYS.session), [])

export const clearSessionQuestions = () => {
  localStorage.removeItem(STORAGE_KEYS.session)
}

export const saveSessionResult = (result: QuizResult) => {
  localStorage.setItem(STORAGE_KEYS.result, JSON.stringify(result))
}

export const loadSessionResult = (): QuizResult | null =>
  safeJsonParse<QuizResult | null>(localStorage.getItem(STORAGE_KEYS.result), null)
