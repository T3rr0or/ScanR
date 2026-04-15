import { useAuthStore } from '@/store/auth'
import Login from '@/pages/Login'
import Layout from '@/components/Layout'

export default function App() {
  const token = useAuthStore((s) => s.token)
  if (!token) return <Login />
  return <Layout />
}
