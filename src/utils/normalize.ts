export const normalizeAbbreviation = (value: string): string => {
  return value
    .trim()
    .replace(/\s+/g, ' ')
    .replace(/\s*\/\s*/g, '/')
    .toUpperCase()
}

export const normalizeForSplitOptions = (value: string): string[] => {
  return value
    .split('・')
    .map((item) => normalizeAbbreviation(item))
    .filter(Boolean)
}
