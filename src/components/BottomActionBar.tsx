import type { ReactNode } from 'react'

type Props = {
  children: ReactNode
}

export const BottomActionBar = ({ children }: Props) => {
  return <div className="sticky bottom-0 mt-4 bg-slate-50/95 py-3 backdrop-blur">{children}</div>
}
