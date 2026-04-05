import React, { useState, useEffect, useRef, useCallback } from "react";
import {
  View,
  Text,
  Image,
  TouchableOpacity,
  StyleSheet,
  Modal,
  TextInput,
  Alert,
  ActivityIndicator,
  Platform,
  ScrollView,
  Animated,
} from "react-native";
import { useRouter } from "expo-router";
import { Ionicons } from "@expo/vector-icons";
import AsyncStorage from "@react-native-async-storage/async-storage";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { useAuth } from "../../../src/auth/AuthContext";
import { apiClient } from "../../../src/api/apiClient";

type UserProfile = {
  nickname: string;
  email: string;
  profileImage: any;
};

export default function MyPage() {
  const router = useRouter();
  const insets = useSafeAreaInsets();
  const { isLoggedIn, logout } = useAuth();

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
    try {
      if (isLoggedIn) {
        const res = await apiClient.get("/api/users/me");
        const data = res.data;
        setUserProfile({
          nickname: data.displayName || data.name || "사용자",
          email: data.email || "",
          profileImage: data.picture
            ? { uri: data.picture }
            : require("../../../assets/knight/basic_profile.png"),
        });
      } else {
        setUserProfile({
          nickname: "게스트",
          email: "로그인이 필요합니다",
          profileImage: require("../../../assets/knight/basic_profile.png"),
        });
      }
    } catch (error) {
      console.error("유저 정보 로딩 실패:", error);
      setUserProfile({
        nickname: "사용자",
        email: "",
        profileImage: require("../../../assets/knight/basic_profile.png"),
      });
    } finally {
      setIsLoading(false);
    }
  }, [isLoggedIn]);

  useEffect(() => {
    fetchAllData();
  }, [fetchAllData]);

  const saveFeedbackDraft = async (text: string) => {
    try { await AsyncStorage.setItem(FEEDBACK_STORAGE_KEY, text); } catch (e) {}
  };
  const loadFeedbackDraft = async (): Promise<string> => {
    try { return (await AsyncStorage.getItem(FEEDBACK_STORAGE_KEY)) || ""; } catch { return ""; }
  };
  const deleteFeedbackDraft = async () => {
    try { await AsyncStorage.removeItem(FEEDBACK_STORAGE_KEY); } catch (e) {}
  };

  useEffect(() => {
    if (feedbackModalVisible) {
      setIsLoadingFeedback(true);
      loadFeedbackDraft().then((savedText) => {
        setFeedbackText(savedText);
        setIsLoadingFeedback(false);
      });
    }
  }, [feedbackModalVisible]);

  const handleFeedbackModalClose = () => {
    if (feedbackText.trim() !== "") {
      saveFeedbackDraft(feedbackText);
    } else {
      deleteFeedbackDraft();
    }
    setFeedbackModalVisible(false);
  };

  const openEditModal = () => {
    if (!userProfile) return;
    setInputText(userProfile.nickname);
    setModalVisible(true);
  };

  const handleSaveNickname = async () => {
    if (inputText.trim() === "") {
      Alert.alert("알림", "닉네임을 입력해주세요.");
      return;
    }
    try {
      await apiClient.put("/api/users/nickname", { nickname: inputText.trim() });
      setUserProfile((prev) => prev ? { ...prev, nickname: inputText.trim() } : null);
      setModalVisible(false);
    } catch (error) {
      Alert.alert("오류", "닉네임 수정에 실패했습니다.");
    }
  };

  const showThankYouToast = () => {
    setToastVisible(true);
    Animated.timing(fadeAnim, { toValue: 1, duration: 300, useNativeDriver: true }).start();
    setTimeout(() => {
      Animated.timing(fadeAnim, { toValue: 0, duration: 300, useNativeDriver: true }).start(() => {
        setToastVisible(false);
      });
    }, 2000);
  };

  const handleSubmitFeedback = async () => {
    if (feedbackText.trim() === "") {
      Alert.alert("알림", "피드백을 입력해주세요.");
      return;
    }
    setIsSubmittingFeedback(true);
    try {
      await apiClient.post("/api/feedback", { content: feedbackText });
      await deleteFeedbackDraft();
      setFeedbackModalVisible(false);
      setFeedbackText("");
      showThankYouToast();
    } catch (error) {
      Alert.alert("오류", "소리함 전송에 실패했습니다.");
    } finally {
      setIsSubmittingFeedback(false);
    }
  };

  const handleLogout = () => {
    if (Platform.OS === "web") {
      if (window.confirm("정말 로그아웃 하시겠습니까?")) {
        logout().then(() => router.replace("/(auth)/login"));
      }
    } else {
      Alert.alert("로그아웃", "정말 로그아웃 하시겠습니까?", [
        { text: "취소", style: "cancel" },
        {
          text: "로그아웃",
          style: "destructive",
          onPress: async () => {
            await logout();
            router.replace("/(auth)/login");
          },
        },
      ]);
    }
  };

  const renderHeader = () => {
    if (!userProfile) return null;
    return (
      <View style={[styles.headerSection, { paddingTop: insets.top + 10 }]}>
        <View style={styles.navBar}>
          <TouchableOpacity onPress={() => router.back()} style={styles.backButton}>
            <Ionicons name="chevron-back" size={28} color="#1A1A1A" />
          </TouchableOpacity>
          <View style={{ width: 28 }} />
        </View>

        <TouchableOpacity style={styles.trendyCard} activeOpacity={0.9} onPress={openEditModal}>
          <View style={styles.profileLeft}>
            <Image source={userProfile.profileImage} style={styles.trendyImage} />
          </View>
          <View style={styles.profileRight}>
            <View style={styles.nameRow}>
              <Text style={styles.userName}>{userProfile.nickname}</Text>
              <Ionicons name="pencil" size={16} color="#999" />
            </View>
            <Text style={styles.userId}>{userProfile.email}</Text>
          </View>
        </TouchableOpacity>
      </View>
    );
  };

  const renderFeedbackSection = () => (
    <View style={styles.feedbackSection}>
      <View style={styles.sectionHeader}>
        <Text style={styles.sectionTitle}>고객 소리함</Text>
        <Text style={styles.sectionDescription}>의견이나 건의사항을 알려주세요</Text>
      </View>
      <TouchableOpacity style={styles.feedbackButton} activeOpacity={0.8} onPress={() => setFeedbackModalVisible(true)}>
        <View style={styles.feedbackIconContainer}>
          <Ionicons name="mail-outline" size={20} color="#007AFF" />
        </View>
        <Text style={styles.feedbackButtonText}>피드백 보내기</Text>
        <Ionicons name="chevron-forward" size={20} color="#C7C7CC" />
      </TouchableOpacity>
    </View>
  );

  const renderAuthSection = () => {
    if (isLoggedIn) {
      return (
        <View style={styles.logoutSection}>
          <TouchableOpacity style={styles.logoutButton} activeOpacity={0.8} onPress={handleLogout}>
            <View style={styles.feedbackIconContainer}>
              <Ionicons name="log-out-outline" size={20} color="#FF3B30" />
            </View>
            <Text style={styles.logoutButtonText}>로그아웃</Text>
            <Ionicons name="chevron-forward" size={20} color="#C7C7CC" />
          </TouchableOpacity>
        </View>
      );
    }
    return (
      <View style={styles.logoutSection}>
        <TouchableOpacity
          style={[styles.logoutButton, { borderColor: "#E8F4FD" }]}
          activeOpacity={0.8}
          onPress={() => router.push("/(auth)/login")}
        >
          <View style={[styles.feedbackIconContainer, { backgroundColor: "#E8F4FD" }]}>
            <Ionicons name="log-in-outline" size={20} color="#007AFF" />
          </View>
          <Text style={[styles.logoutButtonText, { color: "#007AFF" }]}>로그인</Text>
          <Ionicons name="chevron-forward" size={20} color="#C7C7CC" />
        </TouchableOpacity>
      </View>
    );
  };

  return (
    <View style={styles.container}>
      {isLoading ? (
        <View style={styles.loadingContainer}>
          <ActivityIndicator size="large" color="#4A8CFF" />
          <Text style={styles.loadingText}>정보를 불러오는 중...</Text>
        </View>
      ) : (
        <ScrollView style={{ flex: 1 }} contentContainerStyle={{ paddingBottom: 40 }}>
          {renderHeader()}
          <View style={{ paddingHorizontal: 24, paddingTop: 20 }}>
            <Text style={{ color: "#8E8E93", fontSize: 14 }}>내 정보 및 설정을 확인하세요.</Text>
          </View>
          {renderFeedbackSection()}
          {renderAuthSection()}
        </ScrollView>
      )}

      {/* 닉네임 수정 모달 */}
      <Modal animationType="fade" transparent visible={modalVisible} onRequestClose={() => setModalVisible(false)}>
        <View style={styles.modalOverlay}>
          <View style={styles.modalContent}>
            <Text style={styles.modalTitle}>닉네임 수정</Text>
            <TextInput style={styles.input} value={inputText} onChangeText={setInputText} placeholder="새로운 닉네임을 입력하세요" autoFocus />
            <View style={styles.modalButtons}>
              <TouchableOpacity style={[styles.modalBtn, styles.cancelBtn]} onPress={() => setModalVisible(false)}>
                <Text style={styles.cancelText}>취소</Text>
              </TouchableOpacity>
              <TouchableOpacity style={[styles.modalBtn, styles.saveBtn]} onPress={handleSaveNickname}>
                <Text style={styles.saveText}>저장</Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>

      {/* 고객 소리함 모달 */}
      <Modal animationType="slide" transparent visible={feedbackModalVisible} onRequestClose={handleFeedbackModalClose}>
        <View style={styles.modalOverlay}>
          <View style={styles.feedbackModalContent}>
            <View style={styles.feedbackHeader}>
              <Text style={styles.feedbackModalTitle}>고객 소리함</Text>
              <TouchableOpacity style={styles.closeButton} onPress={handleFeedbackModalClose} disabled={isSubmittingFeedback}>
                <Ionicons name="close" size={28} color="#1A1A1A" />
              </TouchableOpacity>
            </View>
            <Text style={styles.feedbackModalDescription}>소중한 의견을 남겨주세요.{"\n"}서비스 개선에 큰 도움이 됩니다.</Text>
            {isLoadingFeedback ? (
              <View style={styles.loadingContainer}>
                <ActivityIndicator size="small" color="#007AFF" />
                <Text style={styles.loadingText}>내용 불러오는 중...</Text>
              </View>
            ) : (
              <TextInput
                style={styles.feedbackInput}
                value={feedbackText}
                onChangeText={setFeedbackText}
                placeholder="여기에 내용을 입력하세요..."
                placeholderTextColor="#C7C7CC"
                multiline
                numberOfLines={8}
                textAlignVertical="top"
                editable={!isSubmittingFeedback && !isLoadingFeedback}
                maxLength={MAX_LENGTH}
              />
            )}
            <View style={styles.charCountContainer}>
              <Text style={[styles.charCount, feedbackText.length >= MAX_LENGTH && styles.charCountWarning]}>
                {feedbackText.length} / {MAX_LENGTH}
              </Text>
            </View>
            <View style={styles.feedbackModalButtons}>
              <TouchableOpacity style={[styles.feedbackModalBtn, styles.feedbackCancelBtn]} onPress={handleFeedbackModalClose} disabled={isSubmittingFeedback}>
                <Text style={styles.feedbackCancelText}>취소</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={[styles.feedbackModalBtn, styles.feedbackSubmitBtn, (isSubmittingFeedback || feedbackText.trim() === "") && styles.submitBtnDisabled]}
                onPress={handleSubmitFeedback}
                disabled={isSubmittingFeedback || feedbackText.trim() === ""}
              >
                {isSubmittingFeedback ? <ActivityIndicator size="small" color="white" /> : <Text style={styles.feedbackSubmitText}>보내기</Text>}
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>

      {toastVisible && (
        <Animated.View style={[styles.toastContainer, { opacity: fadeAnim }]}>
          <Ionicons name="checkmark-circle" size={20} color="white" style={{ marginRight: 8 }} />
          <Text style={styles.toastText}>소중한 의견 감사합니다!</Text>
        </Animated.View>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#F5FAFF" },
  headerSection: { paddingHorizontal: 20, paddingBottom: 24, backgroundColor: "#F5FAFF" },
  navBar: { flexDirection: "row", justifyContent: "space-between", alignItems: "center", marginBottom: 20 },
  backButton: { padding: 4, marginLeft: -4 },
  trendyCard: {
    flexDirection: "row", alignItems: "center", backgroundColor: "#ffffff", padding: 24, borderRadius: 24,
    ...Platform.select({ ios: { shadowColor: "#000", shadowOffset: { width: 0, height: 4 }, shadowOpacity: 0.08, shadowRadius: 16 }, android: { elevation: 4 } }),
    borderWidth: 1, borderColor: "rgba(242, 244, 246, 0.8)",
  },
  profileLeft: { marginRight: 20 },
  trendyImage: { width: 76, height: 76, borderRadius: 38, backgroundColor: "#F2F4F6", borderWidth: 3, borderColor: "#fff" },
  profileRight: { flex: 1, justifyContent: "center" },
  nameRow: { flexDirection: "row", alignItems: "center", marginBottom: 6 },
  userName: { fontSize: 20, fontWeight: "700", color: "#1A1A1A", marginRight: 6 },
  userId: { fontSize: 14, color: "#8E8E93", fontWeight: "400" },
  loadingContainer: { flex: 1, justifyContent: "center", alignItems: "center" },
  loadingText: { marginTop: 12, color: "#8E8E93", fontSize: 15 },
  feedbackSection: { marginTop: 32, marginHorizontal: 20, paddingBottom: 20 },
  sectionHeader: { marginBottom: 16 },
  sectionTitle: { fontSize: 18, fontWeight: "700", color: "#1A1A1A", marginBottom: 6 },
  sectionDescription: { fontSize: 14, color: "#8E8E93", fontWeight: "400" },
  feedbackButton: {
    flexDirection: "row", alignItems: "center", backgroundColor: "#ffffff", paddingHorizontal: 20, paddingVertical: 18, borderRadius: 16,
    ...Platform.select({ ios: { shadowColor: "#000", shadowOffset: { width: 0, height: 2 }, shadowOpacity: 0.05, shadowRadius: 8 }, android: { elevation: 2 } }),
    borderWidth: 1, borderColor: "#F2F4F6",
  },
  feedbackIconContainer: { marginRight: 12, padding: 6, backgroundColor: "#F0F8FF", borderRadius: 8 },
  feedbackButtonText: { fontSize: 16, fontWeight: "600", color: "#1A1A1A", flex: 1 },
  logoutSection: { marginTop: 12, marginHorizontal: 20 },
  logoutButton: {
    flexDirection: "row", alignItems: "center", backgroundColor: "#ffffff", paddingHorizontal: 20, paddingVertical: 18, borderRadius: 16,
    ...Platform.select({ ios: { shadowColor: "#000", shadowOffset: { width: 0, height: 2 }, shadowOpacity: 0.05, shadowRadius: 8 }, android: { elevation: 2 } }),
    borderWidth: 1, borderColor: "#F2F4F6",
  },
  logoutButtonText: { fontSize: 16, fontWeight: "600", color: "#FF3B30", flex: 1 },
  modalOverlay: { flex: 1, backgroundColor: "rgba(0,0,0,0.5)", justifyContent: "center", alignItems: "center" },
  modalContent: { width: "85%", backgroundColor: "white", borderRadius: 24, padding: 24, alignItems: "center", elevation: 5 },
  modalTitle: { fontSize: 18, fontWeight: "700", marginBottom: 20, color: "#1A1A1A" },
  input: { width: "100%", height: 50, borderWidth: 1, borderColor: "#E5E5EA", borderRadius: 12, paddingHorizontal: 16, marginBottom: 24, fontSize: 16, backgroundColor: "#FAFBFC" },
  modalButtons: { flexDirection: "row", width: "100%", gap: 12 },
  modalBtn: { flex: 1, paddingVertical: 14, borderRadius: 12, alignItems: "center", justifyContent: "center" },
  cancelBtn: { backgroundColor: "#F2F4F6" },
  saveBtn: { backgroundColor: "#007AFF" },
  cancelText: { fontSize: 16, color: "#666", fontWeight: "600" },
  saveText: { fontSize: 16, color: "white", fontWeight: "600" },
  feedbackModalContent: {
    width: "90%", backgroundColor: "white", borderRadius: 28, padding: 24, paddingBottom: 28, maxHeight: "85%", elevation: 8,
    ...Platform.select({ ios: { shadowColor: "#000", shadowOffset: { width: 0, height: 10 }, shadowOpacity: 0.2, shadowRadius: 20 } }),
  },
  feedbackHeader: { flexDirection: "row", alignItems: "center", justifyContent: "space-between", marginBottom: 12 },
  closeButton: { padding: 4, marginRight: -4 },
  feedbackModalTitle: { fontSize: 22, fontWeight: "800", color: "#1A1A1A" },
  feedbackModalDescription: { fontSize: 14, color: "#666", fontWeight: "400", marginBottom: 20, lineHeight: 20 },
  feedbackInput: { width: "100%", minHeight: 180, borderWidth: 1, borderColor: "#E5E5EA", borderRadius: 16, padding: 16, marginBottom: 12, fontSize: 16, lineHeight: 24, backgroundColor: "#FAFBFC", color: "#1A1A1A", textAlignVertical: "top" },
  charCountContainer: { flexDirection: "row", justifyContent: "flex-end", alignItems: "center", marginBottom: 24, paddingHorizontal: 2 },
  charCount: { fontSize: 12, color: "#8E8E93" },
  charCountWarning: { color: "#FF3B30" },
  feedbackModalButtons: { flexDirection: "row", width: "100%", gap: 12 },
  feedbackModalBtn: { flex: 1, paddingVertical: 16, borderRadius: 14, alignItems: "center", justifyContent: "center" },
  feedbackCancelBtn: { backgroundColor: "#F2F4F6" },
  feedbackSubmitBtn: { backgroundColor: "#007AFF", shadowColor: "#007AFF", shadowOffset: { width: 0, height: 4 }, shadowOpacity: 0.2, shadowRadius: 8, elevation: 4 },
  submitBtnDisabled: { opacity: 0.6, backgroundColor: "#A0C8FF", shadowOpacity: 0, elevation: 0 },
  feedbackCancelText: { fontSize: 16, color: "#666", fontWeight: "600" },
  feedbackSubmitText: { fontSize: 16, color: "white", fontWeight: "700" },
  toastContainer: {
    position: "absolute", bottom: 40, left: 20, right: 20, backgroundColor: "rgba(0, 0, 0, 0.8)", paddingVertical: 16, paddingHorizontal: 24, borderRadius: 30,
    flexDirection: "row", alignItems: "center", justifyContent: "center", shadowColor: "#000", shadowOffset: { width: 0, height: 4 }, shadowOpacity: 0.2, shadowRadius: 8, elevation: 6,
  },
  toastText: { color: "white", fontSize: 15, fontWeight: "600" },
});
