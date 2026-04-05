import React, { useState } from "react"
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  Image,
  StyleSheet,
  useWindowDimensions,
  Alert,
  KeyboardAvoidingView,
  Platform,
  ScrollView,
} from "react-native"
import { useAuth } from "../../src/auth/AuthContext"
import { useRouter } from "expo-router"
import { apiClient } from "../../src/api/apiClient"

export default function Login() {
  const { width, height } = useWindowDimensions()
  const { login } = useAuth()
  const router = useRouter()

  const [isSignup, setIsSignup] = useState(false)
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [name, setName] = useState("")
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")

  const handleLogin = async () => {
    if (!email.trim() || !password.trim()) {
      setError("이메일과 비밀번호를 입력해주세요.")
      return
    }
    setError("")
    setLoading(true)
    try {
      const res = await apiClient.post("/auth/login", { email: email.trim(), password })
      await login(res.data.accessToken, res.data.refreshToken)
      router.replace("/(tabs)")
    } catch (e: any) {
      const msg = e.response?.data?.message || "로그인에 실패했습니다."
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  const handleSignup = async () => {
    if (!email.trim() || !password.trim() || !name.trim()) {
      setError("모든 항목을 입력해주세요.")
      return
    }
    if (password.length < 8) {
      setError("비밀번호는 8자 이상이어야 합니다.")
      return
    }
    setError("")
    setLoading(true)
    try {
      const res = await apiClient.post("/auth/signup", {
        email: email.trim(),
        password,
        name: name.trim(),
      })
      await login(res.data.accessToken, res.data.refreshToken)
      router.replace("/(tabs)")
    } catch (e: any) {
      const msg = e.response?.data?.message || "회원가입에 실패했습니다."
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  return (
    <KeyboardAvoidingView
      style={{ flex: 1 }}
      behavior={Platform.OS === "ios" ? "padding" : undefined}
    >
      <ScrollView
        contentContainerStyle={styles.container}
        keyboardShouldPersistTaps="handled"
      >
        <Image
          source={require("../../assets/knight/hand.png")}
          style={[{ width: width * 0.45, height: height * 0.18, marginBottom: 12 }]}
          resizeMode="contain"
        />

        <Text style={styles.title}>한입기사</Text>
        <Text style={styles.subtitle}>One Bite Article</Text>

        <View style={styles.formWrap}>
          {isSignup && (
            <TextInput
              style={styles.input}
              placeholder="이름"
              placeholderTextColor="#AAA"
              value={name}
              onChangeText={setName}
              autoCapitalize="none"
              maxLength={20}
            />
          )}

          <TextInput
            style={styles.input}
            placeholder="이메일"
            placeholderTextColor="#AAA"
            value={email}
            onChangeText={setEmail}
            keyboardType="email-address"
            autoCapitalize="none"
            autoComplete="email"
          />

          <TextInput
            style={styles.input}
            placeholder="비밀번호"
            placeholderTextColor="#AAA"
            value={password}
            onChangeText={setPassword}
            secureTextEntry
            autoCapitalize="none"
            maxLength={30}
          />

          {error ? <Text style={styles.errorText}>{error}</Text> : null}

          <TouchableOpacity
            style={[styles.primaryBtn, loading && styles.disabledBtn]}
            onPress={isSignup ? handleSignup : handleLogin}
            disabled={loading}
          >
            <Text style={styles.primaryBtnText}>
              {loading ? "처리 중..." : isSignup ? "회원가입" : "로그인"}
            </Text>
          </TouchableOpacity>

          <TouchableOpacity
            style={styles.switchBtn}
            onPress={() => {
              setIsSignup(!isSignup)
              setError("")
            }}
          >
            <Text style={styles.switchText}>
              {isSignup
                ? "이미 계정이 있으신가요? 로그인"
                : "계정이 없으신가요? 회원가입"}
            </Text>
          </TouchableOpacity>

          {isSignup && (
            <Text style={styles.hintText}>
              비밀번호: 8자 이상, 영문/숫자/특수문자 포함
            </Text>
          )}
        </View>
      </ScrollView>
    </KeyboardAvoidingView>
  )
}

const styles = StyleSheet.create({
  container: {
    flexGrow: 1,
    justifyContent: "center",
    alignItems: "center",
    paddingHorizontal: 16,
    paddingVertical: 40,
  },
  title: { fontSize: 32, fontWeight: "800", color: "#333" },
  subtitle: { fontSize: 16, color: "#666", marginTop: 4, marginBottom: 36 },
  formWrap: { width: "85%", gap: 12, alignItems: "center" },
  input: {
    width: "100%",
    height: 50,
    backgroundColor: "#FFF",
    borderWidth: 1,
    borderColor: "#DDD",
    borderRadius: 12,
    paddingHorizontal: 16,
    fontSize: 15,
    color: "#222",
  },
  primaryBtn: {
    width: "100%",
    paddingVertical: 15,
    borderRadius: 12,
    backgroundColor: "#87CEEB",
    alignItems: "center",
    marginTop: 4,
  },
  disabledBtn: {
    opacity: 0.6,
  },
  primaryBtnText: {
    fontSize: 16,
    fontWeight: "700",
    color: "#FFF",
  },
  switchBtn: {
    marginTop: 8,
  },
  switchText: {
    fontSize: 14,
    color: "#87CEEB",
    fontWeight: "600",
  },
  errorText: {
    color: "#E74C3C",
    fontSize: 13,
    textAlign: "center",
    width: "100%",
  },
  hintText: {
    color: "#999",
    fontSize: 12,
    textAlign: "center",
    marginTop: 4,
  },
})
