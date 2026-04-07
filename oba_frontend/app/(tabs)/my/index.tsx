import React, { useState, useEffect, useRef, useCallback } from "react";
import {
  View, Text, Image, TouchableOpacity, StyleSheet, Modal, TextInput,
  Alert, ActivityIndicator, Platform, ScrollView, Animated,
} from "react-native";
import { useRouter } from "expo-router";
import { Ionicons } from "@expo/vector-icons";
import AsyncStorage from "@react-native-async-storage/async-storage";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { useAuth } from "../../../src/auth/AuthContext";
import { apiClient } from "../../../src/api/apiClient";
import { COLORS, RADIUS, SHADOWS, TYPO, SPACING } from "../../../constants/theme";

type UserProfile = { nickname: string; email: string; profileImage: any };

export default function MyPage() {
  const router = useRouter();
  const insets = useSafeAreaInsets();
  const { isLoggedIn, isLoading: authLoading, logout } = useAuth();

  const [userProfile, setUserProfile] = useState<UserProfile | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [modalVisible, setModalVisible] = useState(false);
  const [inputText, setInputText] = useState("");
  const [feedbackModalVisible, setFeedbackModalVisible] = useState(false);
  const [feedbackText, setFeedbackText] = useState("");
  const [isSubmittingFeedback, setIsSubmittingFeedback] = useState(false);
  const [isLoadingFeedback, setIsLoadingFeedback] = useState(false);
  const fadeAnim = useRef(new Animated.Value(0)).current;
  const [toastVisible, setToastVisible] = useState(false);
  const MAX_LENGTH = 700;
  const FEEDBACK_STORAGE_KEY = "oba_feedback_draft";

  const fetchAllData = useCallback(async () => {
    if (authLoading) return;
    try {
      if (isLoggedIn) {
        const res = await apiClient.get("/api/users/me");
        const data = res.data;
        const profile = {
          nickname: data.nickname || data.displayName || data.name || "한입기사님",
          email: data.email || "",
          profileImage: data.picture ? { uri: data.picture } : require("../../../assets/knight/basic_profile.png"),
        };
        setUserProfile(profile);
        // 프로필 캐싱 (새로고침 시 API 실패 대비)
        try { await AsyncStorage.setItem("oba_cached_profile", JSON.stringify({ nickname: profile.nickname, email: profile.email, picture: data.picture || "" })); } catch {}
      } else {
        setUserProfile({ nickname: "게스트", email: "로그인이 필요합니다",
          profileImage: require("../../../assets/knight/basic_profile.png") });
      }
    } catch {
      // API 실패 시 캐시된 프로필 사용
      try {
        const cached = await AsyncStorage.getItem("oba_cached_profile");
        if (cached) {
          const parsed = JSON.parse(cached);
          setUserProfile({ nickname: parsed.nickname, email: parsed.email,
            profileImage: parsed.picture ? { uri: parsed.picture } : require("../../../assets/knight/basic_profile.png") });
        } else {
          setUserProfile({ nickname: "한입기사님", email: "",
            profileImage: require("../../../assets/knight/basic_profile.png") });
        }
      } catch {
        setUserProfile({ nickname: "한입기사님", email: "",
          profileImage: require("../../../assets/knight/basic_profile.png") });
      }
    } finally { setIsLoading(false); }
  }, [isLoggedIn, authLoading]);

  useEffect(() => { fetchAllData(); }, [fetchAllData]);

  const saveFeedbackDraft = async (text: string) => { try { await AsyncStorage.setItem(FEEDBACK_STORAGE_KEY, text); } catch {} };
  const loadFeedbackDraft = async (): Promise<string> => { try { return (await AsyncStorage.getItem(FEEDBACK_STORAGE_KEY)) || ""; } catch { return ""; } };
  const deleteFeedbackDraft = async () => { try { await AsyncStorage.removeItem(FEEDBACK_STORAGE_KEY); } catch {} };

  useEffect(() => {
    if (feedbackModalVisible) { setIsLoadingFeedback(true); loadFeedbackDraft().then((s) => { setFeedbackText(s); setIsLoadingFeedback(false); }); }
  }, [feedbackModalVisible]);

  const handleFeedbackModalClose = () => {
    if (feedbackText.trim() !== "") saveFeedbackDraft(feedbackText); else deleteFeedbackDraft();
    setFeedbackModalVisible(false);
  };
  const openEditModal = () => { if (!userProfile) return; setInputText(userProfile.nickname); setModalVisible(true); };
  const handleSaveNickname = async () => {
    if (inputText.trim() === "") { Alert.alert("알림", "닉네임을 입력해주세요."); return; }
    try { await apiClient.put("/api/users/nickname", { nickname: inputText.trim() }); setUserProfile((p) => p ? { ...p, nickname: inputText.trim() } : null); setModalVisible(false); }
    catch { Alert.alert("오류", "닉네임 수정에 실패했습니다."); }
  };
  const showThankYouToast = () => {
    setToastVisible(true);
    Animated.timing(fadeAnim, { toValue: 1, duration: 300, useNativeDriver: true }).start();
    setTimeout(() => { Animated.timing(fadeAnim, { toValue: 0, duration: 300, useNativeDriver: true }).start(() => setToastVisible(false)); }, 2000);
  };
  const handleSubmitFeedback = async () => {
    if (feedbackText.trim() === "") { Alert.alert("알림", "피드백을 입력해주세요."); return; }
    setIsSubmittingFeedback(true);
    try { await apiClient.post("/api/feedback", { content: feedbackText }); await deleteFeedbackDraft(); setFeedbackModalVisible(false); setFeedbackText(""); showThankYouToast(); }
    catch { Alert.alert("오류", "소리함 전송에 실패했습니다."); } finally { setIsSubmittingFeedback(false); }
  };
  const handleLogout = () => {
    if (Platform.OS === "web") { if (window.confirm("정말 로그아웃 하시겠습니까?")) { logout().then(() => router.replace("/(auth)/login")); } }
    else { Alert.alert("로그아웃", "정말 로그아웃 하시겠습니까?", [{ text: "취소", style: "cancel" }, { text: "로그아웃", style: "destructive", onPress: async () => { await logout(); router.replace("/(auth)/login"); } }]); }
  };

  if (isLoading) return <View style={[s.loadingContainer, { paddingTop: insets.top }]}><ActivityIndicator size="large" color={COLORS.primary} /><Text style={s.loadingText}>정보를 불러오는 중...</Text></View>;

  return (
    <View style={s.screen}>
      <ScrollView style={{ flex: 1 }} contentContainerStyle={{ paddingBottom: 40 }}>
        {userProfile && (
          <View style={[s.headerSection, { paddingTop: insets.top + 10 }]}>
            <View style={s.navBar}>
              <TouchableOpacity onPress={() => router.push("/(tabs)")} style={s.backButton}><Ionicons name="chevron-back" size={28} color={COLORS.textPrimary} /></TouchableOpacity>
              <Text style={s.navTitle}>마이페이지</Text>
              <View style={{ width: 28 }} />
            </View>
            <TouchableOpacity style={s.profileCard} activeOpacity={0.9} onPress={openEditModal}>
              <View style={s.profileLeft}><Image source={userProfile.profileImage} style={s.profileImage} /></View>
              <View style={s.profileRight}>
                <View style={s.nameRow}><Text style={s.userName}>{userProfile.nickname}</Text><Ionicons name="pencil" size={14} color={COLORS.textTertiary} /></View>
                <Text style={s.userEmail}>{userProfile.email}</Text>
              </View>
            </TouchableOpacity>
          </View>
        )}
        <View style={{ paddingHorizontal: SPACING.xxl, paddingTop: SPACING.xl }}><Text style={[TYPO.bodySm, { color: COLORS.textTertiary }]}>내 정보 및 설정을 확인하세요.</Text></View>
        <View style={s.section}>
          <Text style={s.sectionTitle}>고객 소리함</Text>
          <Text style={s.sectionDesc}>의견이나 건의사항을 알려주세요</Text>
          <TouchableOpacity style={s.menuButton} activeOpacity={0.8} onPress={() => setFeedbackModalVisible(true)}>
            <View style={s.menuIcon}><Ionicons name="mail-outline" size={20} color={COLORS.primaryLight} /></View>
            <Text style={s.menuText}>피드백 보내기</Text><Ionicons name="chevron-forward" size={20} color={COLORS.textPlaceholder} />
          </TouchableOpacity>
        </View>
        <View style={s.section}>
          {isLoggedIn ? (
            <TouchableOpacity style={s.menuButton} activeOpacity={0.8} onPress={handleLogout}>
              <View style={[s.menuIcon, { backgroundColor: COLORS.errorSurface }]}><Ionicons name="log-out-outline" size={20} color={COLORS.error} /></View>
              <Text style={[s.menuText, { color: COLORS.errorLight }]}>로그아웃</Text><Ionicons name="chevron-forward" size={20} color={COLORS.textPlaceholder} />
            </TouchableOpacity>
          ) : (
            <TouchableOpacity style={s.menuButton} activeOpacity={0.8} onPress={() => router.push("/(auth)/login")}>
              <View style={s.menuIcon}><Ionicons name="log-in-outline" size={20} color={COLORS.primaryLight} /></View>
              <Text style={[s.menuText, { color: COLORS.primaryLight }]}>로그인</Text><Ionicons name="chevron-forward" size={20} color={COLORS.textPlaceholder} />
            </TouchableOpacity>
          )}
        </View>
      </ScrollView>

      <Modal animationType="fade" transparent visible={modalVisible} onRequestClose={() => setModalVisible(false)}>
        <View style={s.modalOverlay}><View style={s.modalContent}>
          <Text style={s.modalTitle}>닉네임 수정</Text>
          <TextInput style={s.input} value={inputText} onChangeText={setInputText} placeholder="새로운 닉네임을 입력하세요" placeholderTextColor={COLORS.textPlaceholder} autoFocus />
          <View style={s.modalButtons}>
            <TouchableOpacity style={[s.modalBtn, s.cancelBtn]} onPress={() => setModalVisible(false)}><Text style={s.cancelText}>취소</Text></TouchableOpacity>
            <TouchableOpacity style={[s.modalBtn, s.saveBtn]} onPress={handleSaveNickname}><Text style={s.saveText}>저장</Text></TouchableOpacity>
          </View>
        </View></View>
      </Modal>

      <Modal animationType="slide" transparent visible={feedbackModalVisible} onRequestClose={handleFeedbackModalClose}>
        <View style={s.modalOverlay}><View style={s.feedbackModal}>
          <View style={s.feedbackHeader}><Text style={s.feedbackTitle}>고객 소리함</Text><TouchableOpacity onPress={handleFeedbackModalClose} disabled={isSubmittingFeedback}><Ionicons name="close" size={28} color={COLORS.textPrimary} /></TouchableOpacity></View>
          <Text style={s.feedbackDesc}>소중한 의견을 남겨주세요.{"\n"}서비스 개선에 큰 도움이 됩니다.</Text>
          {isLoadingFeedback ? (<View style={s.loadingContainer}><ActivityIndicator size="small" color={COLORS.primary} /></View>) : (
            <TextInput style={s.feedbackInput} value={feedbackText} onChangeText={setFeedbackText} placeholder="여기에 내용을 입력하세요..." placeholderTextColor={COLORS.textPlaceholder} multiline numberOfLines={8} textAlignVertical="top" editable={!isSubmittingFeedback && !isLoadingFeedback} maxLength={MAX_LENGTH} />
          )}
          <View style={s.charCountContainer}><Text style={[s.charCount, feedbackText.length >= MAX_LENGTH && { color: COLORS.error }]}>{feedbackText.length} / {MAX_LENGTH}</Text></View>
          <View style={s.modalButtons}>
            <TouchableOpacity style={[s.modalBtn, s.cancelBtn]} onPress={handleFeedbackModalClose} disabled={isSubmittingFeedback}><Text style={s.cancelText}>취소</Text></TouchableOpacity>
            <TouchableOpacity style={[s.modalBtn, s.saveBtn, (isSubmittingFeedback || feedbackText.trim() === "") && { opacity: 0.5 }]} onPress={handleSubmitFeedback} disabled={isSubmittingFeedback || feedbackText.trim() === ""}>
              {isSubmittingFeedback ? <ActivityIndicator size="small" color="#fff" /> : <Text style={s.saveText}>보내기</Text>}
            </TouchableOpacity>
          </View>
        </View></View>
      </Modal>

      {toastVisible && (
        <Animated.View style={[s.toastContainer, { opacity: fadeAnim }]}>
          <Ionicons name="checkmark-circle" size={20} color={COLORS.success} style={{ marginRight: 8 }} />
          <Text style={s.toastText}>소중한 의견 감사합니다!</Text>
        </Animated.View>
      )}
    </View>
  );
}

const s = StyleSheet.create({
  screen: { flex: 1, backgroundColor: COLORS.bgPrimary },
  loadingContainer: { flex: 1, justifyContent: "center", alignItems: "center" },
  loadingText: { marginTop: SPACING.md, ...TYPO.bodySm, color: COLORS.textTertiary },
  headerSection: { paddingHorizontal: SPACING.xl, paddingBottom: SPACING.xxl },
  navBar: { flexDirection: "row", justifyContent: "space-between", alignItems: "center", marginBottom: SPACING.xl },
  navTitle: { ...TYPO.h3, color: COLORS.textPrimary },
  backButton: { padding: 4, marginLeft: -4 },
  profileCard: { flexDirection: "row", alignItems: "center", backgroundColor: COLORS.bgCardElevated, padding: SPACING.xxl, borderRadius: RADIUS.card, borderWidth: 1, borderColor: COLORS.glassBorder, ...SHADOWS.md },
  profileLeft: { marginRight: SPACING.xl },
  profileImage: { width: 72, height: 72, borderRadius: 36, backgroundColor: COLORS.bgSecondary, borderWidth: 2, borderColor: COLORS.primary + "50" },
  profileRight: { flex: 1, justifyContent: "center" },
  nameRow: { flexDirection: "row", alignItems: "center", marginBottom: 4 },
  userName: { ...TYPO.h2, color: COLORS.textPrimary, marginRight: 6 },
  userEmail: { ...TYPO.bodySm, color: COLORS.textTertiary },
  section: { marginTop: SPACING.xxxl, marginHorizontal: SPACING.xl },
  sectionTitle: { ...TYPO.h3, color: COLORS.textPrimary, marginBottom: 4 },
  sectionDesc: { ...TYPO.bodySm, color: COLORS.textTertiary, marginBottom: SPACING.lg },
  menuButton: { flexDirection: "row", alignItems: "center", backgroundColor: COLORS.bgCardElevated, paddingHorizontal: SPACING.xl, paddingVertical: SPACING.lg, borderRadius: RADIUS.lg, borderWidth: 1, borderColor: COLORS.glassBorder, ...SHADOWS.sm },
  menuIcon: { marginRight: SPACING.md, padding: 6, backgroundColor: COLORS.primarySurface, borderRadius: RADIUS.sm },
  menuText: { ...TYPO.label, color: COLORS.textPrimary, flex: 1 },
  modalOverlay: { flex: 1, backgroundColor: COLORS.overlay, justifyContent: "center", alignItems: "center", paddingHorizontal: SPACING.xl },
  modalContent: { width: "100%", maxWidth: 400, backgroundColor: COLORS.bgSecondary, borderRadius: RADIUS.card, padding: SPACING.xxl, alignItems: "center", borderWidth: 1, borderColor: COLORS.glassBorder, ...SHADOWS.lg },
  modalTitle: { ...TYPO.h3, color: COLORS.textPrimary, marginBottom: SPACING.xl },
  input: { width: "100%", height: 50, borderWidth: 1, borderColor: COLORS.glassBorder, borderRadius: RADIUS.md, paddingHorizontal: SPACING.lg, marginBottom: SPACING.xxl, ...TYPO.body, backgroundColor: COLORS.bgPrimary, color: COLORS.textPrimary },
  modalButtons: { flexDirection: "row", width: "100%", gap: SPACING.md },
  modalBtn: { flex: 1, paddingVertical: 14, borderRadius: RADIUS.button, alignItems: "center", justifyContent: "center" },
  cancelBtn: { backgroundColor: COLORS.glass, borderWidth: 1, borderColor: COLORS.glassBorder },
  saveBtn: { backgroundColor: COLORS.primary, ...SHADOWS.glow },
  cancelText: { ...TYPO.button, color: COLORS.textSecondary },
  saveText: { ...TYPO.button, color: "#FFFFFF" },
  feedbackModal: { width: "100%", maxWidth: 440, backgroundColor: COLORS.bgSecondary, borderRadius: RADIUS.xxl, padding: SPACING.xxl, paddingBottom: 28, maxHeight: "85%", borderWidth: 1, borderColor: COLORS.glassBorder, ...SHADOWS.lg },
  feedbackHeader: { flexDirection: "row", alignItems: "center", justifyContent: "space-between", marginBottom: SPACING.md },
  feedbackTitle: { ...TYPO.h1, color: COLORS.textPrimary },
  feedbackDesc: { ...TYPO.bodySm, color: COLORS.textTertiary, marginBottom: SPACING.xl, lineHeight: 20 },
  feedbackInput: { width: "100%", minHeight: 180, borderWidth: 1, borderColor: COLORS.glassBorder, borderRadius: RADIUS.lg, padding: SPACING.lg, marginBottom: SPACING.md, ...TYPO.body, backgroundColor: COLORS.bgPrimary, color: COLORS.textPrimary, textAlignVertical: "top" },
  charCountContainer: { flexDirection: "row", justifyContent: "flex-end", marginBottom: SPACING.xxl, paddingHorizontal: 2 },
  charCount: { ...TYPO.caption, color: COLORS.textTertiary },
  toastContainer: { position: "absolute", bottom: 40, left: SPACING.xl, right: SPACING.xl, backgroundColor: COLORS.bgCardElevated, paddingVertical: SPACING.lg, paddingHorizontal: SPACING.xxl, borderRadius: RADIUS.pill, flexDirection: "row", alignItems: "center", justifyContent: "center", borderWidth: 1, borderColor: COLORS.glassBorder, ...SHADOWS.lg },
  toastText: { color: COLORS.textPrimary, ...TYPO.label },
});
