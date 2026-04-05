import { View, Text, TouchableOpacity, Image, StyleSheet, useWindowDimensions, Platform } from "react-native"
import * as WebBrowser from "expo-web-browser"
import * as Linking from "expo-linking"
import { useAuth } from "../../src/auth/AuthContext"
import { useRouter } from "expo-router"

const BASE_URL = "http://onebitearticle.com"

export default function Login() {
  const { width, height } = useWindowDimensions()
  const { login } = useAuth()
  const router = useRouter()

  const handleOAuthLogin = async (provider: "google" | "kakao" | "naver") => {
    const authUrl = `${BASE_URL}/oauth2/authorization/${provider}`

    if (Platform.OS === "web") {
      // 웹: 새 창에서 OAuth 진행 → 콜백으로 토큰 수신
      window.location.href = authUrl
    } else {
      // 모바일: WebBrowser로 OAuth 진행
      const result = await WebBrowser.openAuthSessionAsync(authUrl, Linking.createURL("/oauth/callback"))

      if (result.type === "success" && result.url) {
        const url = new URL(result.url)
        const accessToken = url.searchParams.get("access_token")
        const refreshToken = url.searchParams.get("refresh_token")

        if (accessToken && refreshToken) {
          await login(accessToken, refreshToken)
          router.replace("/(tabs)")
        }
      }
    }
  }

  return (
    <View style={styles.container}>
      <Image
        source={require("../../assets/knight/hand.png")}
        style={[{ width: width * 0.55, height: height * 0.23, marginBottom: 16 }]}
        resizeMode="contain"
      />

      <Text style={styles.title}>한입기사</Text>
      <Text style={styles.subtitle}>One Bite Article</Text>

      <View style={styles.btnWrap}>
        <TouchableOpacity style={[styles.btn, styles.google]} onPress={() => handleOAuthLogin("google")}>
          <Image source={require("../../assets/icons/google.png")} style={styles.icon} />
          <Text style={styles.btnText}>구글로 로그인</Text>
        </TouchableOpacity>

        <TouchableOpacity style={[styles.btn, styles.kakao]} onPress={() => handleOAuthLogin("kakao")}>
          <Image source={require("../../assets/icons/kakao-talk.png")} style={styles.icon} />
          <Text style={[styles.btnText, { color: "#3B1E1E" }]}>카카오로 로그인</Text>
        </TouchableOpacity>

        <TouchableOpacity style={[styles.btn, styles.naver]} onPress={() => handleOAuthLogin("naver")}>
          <Image source={require("../../assets/icons/naver.png")} style={styles.icon} />
          <Text style={styles.btnText}>네이버로 로그인</Text>
        </TouchableOpacity>
      </View>
    </View>
  )
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: "center",
    alignItems: "center",
    paddingHorizontal: 16,
  },
  title: { fontSize: 32, fontWeight: "800", color: "#333" },
  subtitle: { fontSize: 16, color: "#666", marginTop: 4, marginBottom: 42 },
  btnWrap: { width: "85%", gap: 14, alignItems: "center" },
  btn: {
    flexDirection: "row",
    alignItems: "center",
    paddingVertical: 14,
    borderRadius: 12,
    gap: 10,
    justifyContent: "center",
    width: "100%",
  },
  icon: { width: 20, height: 20, resizeMode: "contain" },
  google: { backgroundColor: "#FFF", borderWidth: 1, borderColor: "#DDD" },
  kakao: { backgroundColor: "#FEE500" },
  naver: { backgroundColor: "#03C75A" },
  btnText: { fontSize: 16, fontWeight: "600", color: "#222" },
})
