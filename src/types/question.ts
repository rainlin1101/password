export type Question = {
  id: number
  abbreviation: string
  japanese: string
  english: string
  category: string
  subcategory: string
  source_page: string
}

export type QuizMode = 'all' | 'category' | 'wrong'

export type QuizSession = {
  questions: Question[]
  mode: QuizMode
  category?: string
}

export type QuizResult = {
  total: number
  correct: number
  wrong: number
  accuracy: number
  mode: QuizMode
  category?: string
  finishedAt: string
}
