import { createContext, useContext, useEffect, useState, ReactNode } from "react"
import AsyncStorage from "@react-native-async-storage/async-storage"
import { apiClient } from "../api/apiClient"

interface AuthState {
  accessToken: string | null
  refreshToken: string | null
  isLoading: boolean
  isLoggedIn: boolean
  login: (accessToken: string, refreshToken: string) => Promise<void>
  logout: () => Promise<void>
}

const AuthContext = createContext<AuthState>({
  accessToken: null,
  refreshToken: null,
  isLoading: true,
  isLoggedIn: false,
  login: async () => {},
  logout: async () => {},
})

export function AuthProvider({ children }: { children: ReactNode }) {
  const [accessToken, setAccessToken] = useState<string | null>(null)
  const [refreshToken, setRefreshToken] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)

  // 앱 시작 시 저장된 토큰 불러오기
  useEffect(() => {
    const loadTokens = async () => {
      try {
        const storedAccess = await AsyncStorage.getItem("accessToken")
        const storedRefresh = await AsyncStorage.getItem("refreshToken")
        if (storedAccess) {
          setAccessToken(storedAccess)
          setRefreshToken(storedRefresh)
        }
      } catch (e) {
        console.error("토큰 로드 실패:", e)
      } finally {
        setIsLoading(false)
      }
    }
    loadTokens()
  }, [])

  // accessToken 변경 시 apiClient 헤더 업데이트
  useEffect(() => {
    if (accessToken) {
      apiClient.defaults.headers.common["Authorization"] = `Bearer ${accessToken}`
    } else {
      delete apiClient.defaults.headers.common["Authorization"]
    }
  }, [accessToken])

  // 토큰 리프레시 인터셉터
  useEffect(() => {
    const interceptor = apiClient.interceptors.response.use(
      (response) => response,
      async (error) => {
        const originalRequest = error.config
        if (error.response?.status === 401 && !originalRequest._retry && refreshToken) {
          originalRequest._retry = true
          try {
            const res = await apiClient.post("/auth/reissue", null, {
              headers: { Authorization: `Bearer ${refreshToken}` },
            })
            const newAccess = res.data.accessToken
            const newRefresh = res.data.refreshToken
            await login(newAccess, newRefresh)
            originalRequest.headers["Authorization"] = `Bearer ${newAccess}`
            return apiClient(originalRequest)
          } catch (refreshError) {
            await logout()
            return Promise.reject(refreshError)
          }
        }
        return Promise.reject(error)
      },
    )
    return () => apiClient.interceptors.response.eject(interceptor)
  }, [refreshToken])

  const login = async (newAccess: string, newRefresh: string) => {
    setAccessToken(newAccess)
    setRefreshToken(newRefresh)
    await AsyncStorage.setItem("accessToken", newAccess)
    await AsyncStorage.setItem("refreshToken", newRefresh)
  }

  const logout = async () => {
    setAccessToken(null)
    setRefreshToken(null)
    await AsyncStorage.removeItem("accessToken")
    await AsyncStorage.removeItem("refreshToken")
  }

  return (
    <AuthContext.Provider
      value={{
        accessToken,
        refreshToken,
        isLoading,
        isLoggedIn: !!accessToken,
        login,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => useContext(AuthContext)
