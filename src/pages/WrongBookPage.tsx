import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { AppHeader } from '../components/AppHeader'
import { clearWrongBook, loadWrongBook, removeWrongQuestion } from '../utils/storage'

export const WrongBookPage = () => {
  const navigate = useNavigate()
  const [items, setItems] = useState(() => loadWrongBook())

  const canStart = useMemo(() => items.length > 0, [items])

  const onRemove = (id: number) => {
    removeWrongQuestion(id)
    setItems(loadWrongBook())
  }

  const onClear = () => {
    clearWrongBook()
    setItems([])
  }

  return (
    <div className="space-y-4">
      <AppHeader title="错题本" subtitle={`共 ${items.length} 题`} showHome />

      <div className="grid gap-3">
        <button
          disabled={!canStart}
          onClick={() => navigate('/quiz?mode=wrong')}
          className="rounded-2xl bg-brand-600 px-4 py-3 text-base font-bold text-white disabled:cursor-not-allowed disabled:bg-slate-300"
        >
          只刷错题
        </button>
        <button onClick={onClear} className="rounded-2xl bg-white px-4 py-3 text-base font-semibold text-rose-600 shadow-card">
          清空全部错题
        </button>
      </div>

      <div className="space-y-2">
        {items.map((item) => (
          <div key={item.id} className="rounded-2xl bg-white p-4 shadow-card">
            <p className="text-sm text-slate-500">{item.category}</p>
            <p className="font-bold text-slate-900">{item.japanese}</p>
            <p className="mt-1 text-sm text-slate-600">
              正确答案：<span className="font-semibold">{item.abbreviation}</span>
            </p>
            <button onClick={() => onRemove(item.id)} className="mt-3 rounded-xl bg-slate-100 px-3 py-1.5 text-xs font-semibold text-slate-600">
              删除
            </button>
          </div>
        ))}
      </div>
    </div>
  )
}
