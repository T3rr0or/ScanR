import { create } from 'zustand'
import { persist, createJSONStorage } from 'zustand/middleware'

interface AuthState {
  token: string | null
  setToken: (access: string) => void
  logout: () => void
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      token: null,
      setToken: (access) => set({ token: access }),
      logout: () => set({ token: null }),
    }),
    {
      name: 'scanr-auth',
      storage: createJSONStorage(() => sessionStorage),
    }
  )
)
