import { create } from 'zustand'
import type { LabSession, SimulatedResult } from '../types'

interface LabState {
  sessions: LabSession[]
  addSession: (payload: Omit<LabSession, 'id' | 'timestamp'>) => void
  logResult: (vulnType: string, payload: string, result: SimulatedResult, riskScore: number) => void
}

const STORAGE_KEY = 'vulnlab-sessions'

function loadSessions(): LabSession[] {
  const stored = window.localStorage.getItem(STORAGE_KEY)
  if (!stored) {
    return []
  }

  try {
    return JSON.parse(stored) as LabSession[]
  } catch {
    return []
  }
}

function persistSessions(sessions: LabSession[]) {
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(sessions))
}

export const useLabStore = create<LabState>((set) => ({
  sessions: loadSessions(),
  addSession: (payload) =>
    set((state) => {
      const next: LabSession = {
        ...payload,
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString()
      }
      const sessions = [next, ...state.sessions]
      persistSessions(sessions)
      return { sessions }
    }),
  logResult: (vulnType, payload, result, riskScore) =>
    set((state) => {
      const sessions = [
        {
          id: crypto.randomUUID(),
          timestamp: new Date().toISOString(),
          vulnType,
          payloadsUsed: [payload],
          results: [result],
          riskScore: result.riskScore ?? riskScore
        },
        ...state.sessions
      ]
      persistSessions(sessions)
      return { sessions }
    })
}))
