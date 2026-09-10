import { useEffect, useState } from 'react'

const prefix = 'infrareveal.debug.v3.'
export function readPreference<T>(key: string, fallback: T): T {
  try {
    const value: unknown = JSON.parse(localStorage.getItem(prefix + key) ?? 'null')
    if (!matchesShape(value, fallback)) return fallback
    return value as T
  } catch { return fallback }
}
export function usePreference<T>(key: string, fallback: T) {
  const [value, setValue] = useState<T>(() => readPreference(key, fallback))
  useEffect(() => {
    try { localStorage.setItem(prefix + key, JSON.stringify(value)) } catch { /* Storage is optional. */ }
  }, [key, value])
  return [value, setValue] as const
}

function matchesShape(value: unknown, fallback: unknown): boolean {
  if (value === null || typeof value !== typeof fallback) return false
  if (typeof value === 'number') return Number.isFinite(value)
  if (Array.isArray(fallback)) return Array.isArray(value) && value.every(item => typeof item === 'string')
  if (typeof fallback === 'object' && fallback) return !Array.isArray(value) && Object.entries(fallback).every(([key, sample]) => matchesShape((value as Record<string, unknown>)[key], sample))
  return true
}
