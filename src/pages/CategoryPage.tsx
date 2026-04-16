import { useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { AppHeader } from '../components/AppHeader'
import { CategoryGrid } from '../components/CategoryGrid'
import questions from '../data/questions.json'
import { getCategoryMap } from '../utils/quiz'
import { loadRecentCategory, saveRecentCategory } from '../utils/storage'

export const CategoryPage = () => {
  const navigate = useNavigate()
  const categoryMap = useMemo(() => getCategoryMap(questions), [])
  const recentCategory = useMemo(() => loadRecentCategory(), [])

  const onSelect = (category: string) => {
    saveRecentCategory(category)
    navigate(`/quiz?mode=category&category=${encodeURIComponent(category)}`)
  }

  return (
    <div className="space-y-4">
      <AppHeader title="分类练习" subtitle="选择一个 category 开始" showHome />
      <CategoryGrid categoryMap={categoryMap} onSelect={onSelect} recentCategory={recentCategory} />
    </div>
  )
}
