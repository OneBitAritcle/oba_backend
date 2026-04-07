import React, { useState, useEffect, useRef } from "react"
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  Image,
  StyleSheet,
  useWindowDimensions,
  KeyboardAvoidingView,
  Platform,
  ScrollView,
  ActivityIndicator,
} from "react-native"
import { useAuth } from "../../src/auth/AuthContext"
import { useRouter } from "expo-router"
import { apiClient } from "../../src/api/apiClient"
import { COLORS, RADIUS, SHADOWS, TYPO, SPACING } from "../../constants/theme"

const ALLOWED_DOMAINS = [
  "naver.com", "gmail.com", "daum.net", "kakao.com",
  "hanmail.net", "nate.com", "outlook.com", "hotmail.com",
  "yahoo.com", "icloud.com",
]

type Mode = "login" | "signup" | "reset"

export default function Login() {
  const { width, height } = useWindowDimensions()
  const { login } = useAuth()
  const router = useRouter()

  const [mode, setMode] = useState<Mode>("login")
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [passwordConfirm, setPasswordConfirm] = useState("")
  const [name, setName] = useState("")
  const [newPassword, setNewPassword] = useState("")
  const [newPasswordConfirm, setNewPasswordConfirm] = useState("")
  const [loading, setLoading] = useState(false)
  const [successMsg, setSuccessMsg] = useState("")

  const [emailError, setEmailError] = useState("")
  const [emailChecking, setEmailChecking] = useState(false)
  const [emailAvailable, setEmailAvailable] = useState(false)
  const [pwErrors, setPwErrors] = useState<string[]>([])
  const [confirmError, setConfirmError] = useState("")
  const [serverError, setServerError] = useState("")

  const emailTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    setEmailAvailable(false)
    setEmailError("")
    if (!email.trim()) return
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    if (!emailRegex.test(email)) { setEmailError("올바른 이메일 형식이 아닙니다."); return }
    const domain = email.split("@")[1]?.toLowerCase()
    if (!ALLOWED_DOMAINS.includes(domain)) { setEmailError(`허용된 이메일: ${ALLOWED_DOMAINS.slice(0, 4).join(", ")} 등`); return }
    if (mode === "signup") {
      if (emailTimerRef.current) clearTimeout(emailTimerRef.current)
      setEmailChecking(true)
      emailTimerRef.current = setTimeout(async () => {
        try {
          const res = await apiClient.get(`/auth/check-email?email=${encodeURIComponent(email)}`)
          if (res.data.exists) { setEmailError("이미 사용 중인 이메일입니다."); setEmailAvailable(false) }
          else { setEmailError(""); setEmailAvailable(true) }
        } catch { setEmailError("") }
        finally { setEmailChecking(false) }
      }, 500)
    }
  }, [email, mode])

  const validatePasswordRealtime = (pw: string) => {
    const errors: string[] = []
    if (pw.length > 0) {
      if (pw.length < 8) errors.push("8자 이상")
      if (!/[a-z]/.test(pw)) errors.push("소문자")
      if (!/[A-Z]/.test(pw)) errors.push("대문자")
      if (!/[0-9]/.test(pw)) errors.push("숫자")
      if (!/[@$!%*#?&^()\-_=+]/.test(pw)) errors.push("특수문자")
    }
    setPwErrors(errors)
  }

  useEffect(() => { validatePasswordRealtime(mode === "reset" ? newPassword : password) }, [password, newPassword, mode])

  useEffect(() => {
    if (mode === "signup") { setConfirmError(passwordConfirm && password !== passwordConfirm ? "비밀번호가 일치하지 않습니다." : "") }
    else if (mode === "reset") { setConfirmError(newPasswordConfirm && newPassword !== newPasswordConfirm ? "비밀번호가 일치하지 않습니다." : "") }
  }, [password, passwordConfirm, newPassword, newPasswordConfirm, mode])

  const clearFields = () => { setPassword(""); setPasswordConfirm(""); setName(""); setNewPassword(""); setNewPasswordConfirm(""); setServerError(""); setSuccessMsg(""); setPwErrors([]); setConfirmError("") }

  const handleLogin = async () => {
    if (!email.trim() || !password.trim()) { setServerError("이메일과 비밀번호를 입력해주세요."); return }
    setServerError(""); setLoading(true)
    try { const res = await apiClient.post("/auth/login", { email: email.trim(), password }); await login(res.data.accessToken, res.data.refreshToken); router.replace("/(tabs)") }
    catch (e: any) { setServerError(e.response?.data?.message || "로그인에 실패했습니다.") }
    finally { setLoading(false) }
  }

  const handleSignup = async () => {
    if (!email.trim() || !password || !passwordConfirm || !name.trim()) { setServerError("모든 항목을 입력해주세요."); return }
    if (emailError || pwErrors.length > 0 || confirmError) { setServerError("입력 항목을 확인해주세요."); return }
    setServerError(""); setLoading(true)
    try { const res = await apiClient.post("/auth/signup", { email: email.trim(), password, name: name.trim() }); await login(res.data.accessToken, res.data.refreshToken); router.replace("/(tabs)") }
    catch (e: any) { setServerError(e.response?.data?.message || "회원가입에 실패했습니다.") }
    finally { setLoading(false) }
  }

  const handleResetPassword = async () => {
    if (!email.trim() || !name.trim() || !newPassword || !newPasswordConfirm) { setServerError("모든 항목을 입력해주세요."); return }
    if (emailError || pwErrors.length > 0 || confirmError) { setServerError("입력 항목을 확인해주세요."); return }
    setServerError(""); setLoading(true)
    try { await apiClient.post("/auth/reset-password", { email: email.trim(), name: name.trim(), newPassword }); setSuccessMsg("비밀번호가 재설정되었습니다. 로그인해주세요."); setTimeout(() => { setMode("login"); clearFields() }, 1500) }
    catch (e: any) { setServerError(e.response?.data?.message || "비밀번호 재설정에 실패했습니다.") }
    finally { setLoading(false) }
  }

  const modeTitle = mode === "login" ? "로그인" : mode === "signup" ? "회원가입" : "비밀번호 찾기"

  return (
    <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === "ios" ? "padding" : undefined}>
      <ScrollView contentContainerStyle={s.container} keyboardShouldPersistTaps="handled">
        <Image source={require("../../assets/knight/hand.png")} style={{ width: width * 0.3, height: height * 0.12, marginBottom: 4 }} resizeMode="contain" />
        <Text style={s.title}>한입기사</Text>
        <Text style={s.subtitle}>One Bite Article</Text>

        <View style={s.card}>
          <Text style={s.modeTitle}>{modeTitle}</Text>

          {(mode === "signup" || mode === "reset") && (
            <TextInput style={s.input} placeholder="이름" placeholderTextColor={COLORS.textPlaceholder} value={name} onChangeText={setName} autoCapitalize="none" maxLength={20} />
          )}

          <View style={{ width: "100%" }}>
            <TextInput style={[s.input, emailError ? s.inputError : emailAvailable && mode === "signup" ? s.inputSuccess : null]} placeholder="이메일" placeholderTextColor={COLORS.textPlaceholder} value={email} onChangeText={setEmail} keyboardType="email-address" autoCapitalize="none" autoComplete="email" />
            {emailChecking && <Text style={s.hintText}>확인 중...</Text>}
            {emailError ? <Text style={s.errorSmall}>{emailError}</Text> : null}
            {emailAvailable && mode === "signup" && !emailError && <Text style={s.successSmall}>사용 가능한 이메일입니다.</Text>}
          </View>

          {mode !== "reset" && (
            <View style={{ width: "100%" }}>
              <TextInput style={[s.input, mode === "signup" && pwErrors.length > 0 ? s.inputError : null]} placeholder="비밀번호" placeholderTextColor={COLORS.textPlaceholder} value={password} onChangeText={setPassword} secureTextEntry autoCapitalize="none" maxLength={30} />
              {mode === "signup" && password.length > 0 && (
                <View style={s.pwChecklist}>
                  <PwCheck label="8자 이상" ok={password.length >= 8} />
                  <PwCheck label="소문자" ok={/[a-z]/.test(password)} />
                  <PwCheck label="대문자" ok={/[A-Z]/.test(password)} />
                  <PwCheck label="숫자" ok={/[0-9]/.test(password)} />
                  <PwCheck label="특수문자" ok={/[@$!%*#?&^()\-_=+]/.test(password)} />
                </View>
              )}
            </View>
          )}

          {mode === "signup" && (
            <View style={{ width: "100%" }}>
              <TextInput style={[s.input, confirmError ? s.inputError : passwordConfirm && !confirmError ? s.inputSuccess : null]} placeholder="비밀번호 확인" placeholderTextColor={COLORS.textPlaceholder} value={passwordConfirm} onChangeText={setPasswordConfirm} secureTextEntry autoCapitalize="none" maxLength={30} />
              {confirmError ? <Text style={s.errorSmall}>{confirmError}</Text> : null}
              {passwordConfirm && !confirmError && <Text style={s.successSmall}>비밀번호가 일치합니다.</Text>}
            </View>
          )}

          {mode === "reset" && (
            <>
              <View style={{ width: "100%" }}>
                <TextInput style={[s.input, pwErrors.length > 0 ? s.inputError : null]} placeholder="새 비밀번호" placeholderTextColor={COLORS.textPlaceholder} value={newPassword} onChangeText={setNewPassword} secureTextEntry autoCapitalize="none" maxLength={30} />
                {newPassword.length > 0 && (
                  <View style={s.pwChecklist}>
                    <PwCheck label="8자 이상" ok={newPassword.length >= 8} />
                    <PwCheck label="소문자" ok={/[a-z]/.test(newPassword)} />
                    <PwCheck label="대문자" ok={/[A-Z]/.test(newPassword)} />
                    <PwCheck label="숫자" ok={/[0-9]/.test(newPassword)} />
                    <PwCheck label="특수문자" ok={/[@$!%*#?&^()\-_=+]/.test(newPassword)} />
                  </View>
                )}
              </View>
              <View style={{ width: "100%" }}>
                <TextInput style={[s.input, confirmError ? s.inputError : newPasswordConfirm && !confirmError ? s.inputSuccess : null]} placeholder="새 비밀번호 확인" placeholderTextColor={COLORS.textPlaceholder} value={newPasswordConfirm} onChangeText={setNewPasswordConfirm} secureTextEntry autoCapitalize="none" maxLength={30} />
                {confirmError ? <Text style={s.errorSmall}>{confirmError}</Text> : null}
                {newPasswordConfirm && !confirmError && <Text style={s.successSmall}>비밀번호가 일치합니다.</Text>}
              </View>
            </>
          )}

          {serverError ? <Text style={s.errorText}>{serverError}</Text> : null}
          {successMsg ? <Text style={s.successText}>{successMsg}</Text> : null}

          <TouchableOpacity style={[s.primaryBtn, loading && s.disabledBtn]} onPress={mode === "login" ? handleLogin : mode === "signup" ? handleSignup : handleResetPassword} disabled={loading}>
            {loading ? <ActivityIndicator color="#FFF" size="small" /> : <Text style={s.primaryBtnText}>{mode === "login" ? "로그인" : mode === "signup" ? "회원가입" : "비밀번호 재설정"}</Text>}
          </TouchableOpacity>

          <View style={s.linkRow}>
            {mode === "login" && (
              <>
                <TouchableOpacity onPress={() => { setMode("signup"); clearFields() }}><Text style={s.linkText}>회원가입</Text></TouchableOpacity>
                <Text style={s.linkDivider}>|</Text>
                <TouchableOpacity onPress={() => { setMode("reset"); clearFields() }}><Text style={s.linkText}>비밀번호 찾기</Text></TouchableOpacity>
              </>
            )}
            {mode === "signup" && <TouchableOpacity onPress={() => { setMode("login"); clearFields() }}><Text style={s.linkText}>이미 계정이 있으신가요? 로그인</Text></TouchableOpacity>}
            {mode === "reset" && <TouchableOpacity onPress={() => { setMode("login"); clearFields() }}><Text style={s.linkText}>로그인으로 돌아가기</Text></TouchableOpacity>}
          </View>
        </View>
      </ScrollView>
    </KeyboardAvoidingView>
  )
}

function PwCheck({ label, ok }: { label: string; ok: boolean }) {
  return (
    <View style={[s.pwBadge, ok ? s.pwBadgeOk : s.pwBadgeFail]}>
      <Text style={[s.pwBadgeText, ok ? s.pwTextOk : s.pwTextFail]}>{ok ? "\u2713" : "\u2717"} {label}</Text>
    </View>
  )
}

const s = StyleSheet.create({
  container: {
    flexGrow: 1,
    justifyContent: "center",
    alignItems: "center",
    paddingHorizontal: SPACING.lg,
    paddingVertical: SPACING.xxxl,
  },
  title: {
    ...TYPO.display,
    color: COLORS.textPrimary,
  },
  subtitle: {
    ...TYPO.bodySm,
    color: COLORS.textTertiary,
    marginTop: 2,
    marginBottom: SPACING.xxl,
  },
  card: {
    width: "90%",
    maxWidth: 420,
    backgroundColor: COLORS.bgCardElevated,
    borderRadius: RADIUS.xxl,
    padding: SPACING.xxl,
    gap: SPACING.md,
    alignItems: "center",
    borderWidth: 1,
    borderColor: COLORS.glassBorder,
    ...SHADOWS.lg,
  },
  modeTitle: {
    ...TYPO.h2,
    color: COLORS.textPrimary,
    marginBottom: SPACING.sm,
  },
  input: {
    width: "100%",
    height: 52,
    backgroundColor: COLORS.bgSecondary,
    borderWidth: 1.5,
    borderColor: COLORS.border,
    borderRadius: RADIUS.md,
    paddingHorizontal: SPACING.lg,
    fontSize: 15,
    color: COLORS.textPrimary,
  },
  inputError: { borderColor: COLORS.error },
  inputSuccess: { borderColor: COLORS.success },
  primaryBtn: {
    width: "100%",
    paddingVertical: 16,
    borderRadius: RADIUS.button,
    backgroundColor: COLORS.primary,
    alignItems: "center",
    marginTop: SPACING.sm,
    shadowColor: COLORS.primary,
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.3,
    shadowRadius: 12,
    elevation: 4,
  },
  disabledBtn: { opacity: 0.6 },
  primaryBtnText: {
    ...TYPO.button,
    color: "#FFF",
  },
  linkRow: {
    flexDirection: "row",
    alignItems: "center",
    marginTop: SPACING.md,
    gap: SPACING.md,
  },
  linkText: {
    ...TYPO.label,
    color: COLORS.primaryLight,
  },
  linkDivider: { color: COLORS.divider, fontSize: 14 },
  errorText: { color: COLORS.error, fontSize: 13, textAlign: "center", width: "100%" },
  successText: { color: COLORS.success, fontSize: 13, textAlign: "center", width: "100%" },
  errorSmall: { color: COLORS.error, fontSize: 11, marginTop: 3, marginLeft: 4 },
  successSmall: { color: COLORS.success, fontSize: 11, marginTop: 3, marginLeft: 4 },
  hintText: { color: COLORS.textTertiary, fontSize: 11, marginTop: 3, marginLeft: 4 },
  pwChecklist: { flexDirection: "row", flexWrap: "wrap", gap: 6, marginTop: SPACING.sm, marginLeft: 2 },
  pwBadge: {
    paddingHorizontal: 8,
    paddingVertical: 3,
    borderRadius: RADIUS.sm,
  },
  pwBadgeOk: { backgroundColor: COLORS.successSurface },
  pwBadgeFail: { backgroundColor: COLORS.errorSurface },
  pwBadgeText: { fontSize: 11, fontWeight: "600" },
  pwTextOk: { color: COLORS.success },
  pwTextFail: { color: COLORS.error },
})
