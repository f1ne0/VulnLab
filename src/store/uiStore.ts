import { create } from 'zustand'

interface UiState {
  sidebarCollapsed: boolean
  searchOpen: boolean
  coordinates: { x: number; y: number }
  toggleSidebar: () => void
  setSearchOpen: (value: boolean) => void
  setCoordinates: (x: number, y: number) => void
}

export const useUiStore = create<UiState>((set) => ({
  sidebarCollapsed: false,
  searchOpen: false,
  coordinates: { x: 0, y: 0 },
  toggleSidebar: () =>
    set((state) => ({
      sidebarCollapsed: !state.sidebarCollapsed
    })),
  setSearchOpen: (value) => set({ searchOpen: value }),
  setCoordinates: (x, y) => set({ coordinates: { x, y } })
}))
