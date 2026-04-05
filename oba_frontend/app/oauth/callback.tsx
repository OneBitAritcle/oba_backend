import { useEffect } from "react"
import { View, ActivityIndicator, Text, Platform } from "react-native"
import { useRouter, useLocalSearchParams } from "expo-router"
import { useAuth } from "../../src/auth/AuthContext"

export default function OAuthCallback() {
  const router = useRouter()
  const { login } = useAuth()
  const params = useLocalSearchParams<{ access_token?: string; refresh_token?: string }>()

  useEffect(() => {
    const handleCallback = async () => {
      let accessToken = params.access_token
      let refreshToken = params.refresh_token

      // 웹에서는 URL 쿼리 파라미터에서 직접 추출
      if (Platform.OS === "web" && (!accessToken || !refreshToken)) {
        const urlParams = new URLSearchParams(window.location.search)
        accessToken = urlParams.get("access_token") ?? undefined
        refreshToken = urlParams.get("refresh_token") ?? undefined
      }

      if (accessToken && refreshToken) {
        await login(accessToken, refreshToken)
        router.replace("/(tabs)")
      } else {
        router.replace("/(auth)/login")
      }
    }

    handleCallback()
  }, [])

  return (
    <View style={{ flex: 1, justifyContent: "center", alignItems: "center" }}>
      <ActivityIndicator size="large" color="#007AFF" />
      <Text style={{ marginTop: 16, color: "#666" }}>로그인 중...</Text>
    </View>
  )
}
