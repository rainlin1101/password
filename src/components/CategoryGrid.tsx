type Props = {
  categoryMap: Record<string, number>
  onSelect: (category: string) => void
  recentCategory: string
}

export const CategoryGrid = ({ categoryMap, onSelect, recentCategory }: Props) => {
  return (
    <div className="grid grid-cols-1 gap-3">
      {Object.entries(categoryMap).map(([category, count]) => {
        const active = category === recentCategory
        return (
          <button
            key={category}
            className={`rounded-2xl border p-4 text-left transition active:scale-[0.99] ${
              active ? 'border-brand-500 bg-brand-50' : 'border-slate-200 bg-white'
            }`}
            onClick={() => onSelect(category)}
          >
            <p className="text-base font-bold text-slate-800">{category}</p>
            <p className="mt-1 text-sm text-slate-500">{count} 题</p>
          </button>
        )
      })}
    </div>
  )
}
