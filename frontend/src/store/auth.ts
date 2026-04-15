import { create } from 'zustand'
import { persist, createJSONStorage } from 'zustand/middleware'

interface AuthState {
  token: string | null
  refreshToken: string | null
  setTokens: (access: string, refresh: string) => void
  logout: () => void
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      token: null,
      refreshToken: null,
      setTokens: (access, refresh) => set({ token: access, refreshToken: refresh }),
      logout: () => set({ token: null, refreshToken: null }),
    }),
    {
      name: 'scanr-auth',
      storage: createJSONStorage(() => sessionStorage),
    }
  )
)
