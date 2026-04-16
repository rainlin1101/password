import type { Question } from '../types/question'
import { normalizeAbbreviation, normalizeForSplitOptions } from './normalize'

export const shuffleQuestions = (questions: Question[]): Question[] => {
  const copied = [...questions]
  for (let i = copied.length - 1; i > 0; i -= 1) {
    const j = Math.floor(Math.random() * (i + 1))
    ;[copied[i], copied[j]] = [copied[j], copied[i]]
  }
  return copied
}

export const isAnswerCorrect = (input: string, answer: string): boolean => {
  const userNormalized = normalizeAbbreviation(input)
  const options = normalizeForSplitOptions(answer)
  return options.some((option) => option === userNormalized)
}

export const getCategoryMap = (questions: Question[]): Record<string, number> => {
  return questions.reduce<Record<string, number>>((acc, cur) => {
    acc[cur.category] = (acc[cur.category] ?? 0) + 1
    return acc
  }, {})
}
