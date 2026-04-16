type Props = {
  current: number
  total: number
}

export const ProgressBar = ({ current, total }: Props) => {
  const percent = total === 0 ? 0 : Math.round((current / total) * 100)
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between text-sm font-medium text-slate-600">
        <span>
          进度 {current} / {total}
        </span>
        <span>{percent}%</span>
      </div>
      <div className="h-3 w-full rounded-full bg-slate-100">
        <div
          className="h-3 rounded-full bg-gradient-to-r from-brand-500 to-cyan-400 transition-all duration-300"
          style={{ width: `${percent}%` }}
        />
      </div>
    </div>
  )
}
