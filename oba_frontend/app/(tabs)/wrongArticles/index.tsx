// oba_fronted/app/(tabs)/wrongArticles/index.tsx

import React, { useState, useEffect } from "react";
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  Alert,
  FlatList,
  ActivityIndicator,
  RefreshControl,
  Platform,
} from "react-native";
import { useRouter } from "expo-router";
import { Ionicons } from "@expo/vector-icons";
import { apiClient } from "../../../src/api/apiClient";

// ---------------------------------------------------------
// 1. 데이터 타입 정의 (백엔드와 약속한 데이터 모양)
// ---------------------------------------------------------
type HistoryItem = {
  articleId: string;
  title: string;
  summary: string;
  imageUrl: string;
  category: string;
  solvedAt: string;
};

export default function WrongArticlesPage() {
  const router = useRouter();

  // ---------------------------------------------------------
  // 상태 관리 (State)
  // ---------------------------------------------------------
  const [historyData, setHistoryData] = useState<HistoryItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const [selectedCategory, setSelectedCategory] = useState<string>("All");
  const [categories, setCategories] = useState<string[]>([]);
  const [sortOrder, setSortOrder] = useState<"newest" | "oldest">("newest");

  // ---------------------------------------------------------
  // 데이터 요청
  // ---------------------------------------------------------
  const fetchHistory = async () => {
    try {
      const res = await apiClient.get("/api/my/wrong");
      setHistoryData(res.data);

      const cats = Array.from(new Set(res.data.map((h: HistoryItem) => h.category)));
      setCategories(["All", ...(cats as string[])]);
    } catch (error) {
      console.error("데이터 로딩 실패:", error);
      Alert.alert("오류", "데이터를 불러오지 못했습니다.");
    } finally {
      setIsLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  const onRefresh = () => {
    setRefreshing(true);
    fetchHistory();
  };

  // ---------------------------------------------------------
  // 리스트 헤더 (필터 + 정렬 포함)
  // ---------------------------------------------------------
  const renderHeader = () => (
    <View style={styles.headerSection}>
      <TouchableOpacity onPress={() => router.push("/(tabs)")} style={{ flexDirection: "row", alignItems: "center", marginBottom: 12 }}>
        <Ionicons name="chevron-back" size={24} color="#333" />
        <Text style={{ fontSize: 16, color: "#333", fontWeight: "600" }}>홈</Text>
      </TouchableOpacity>
      <View style={styles.timelineHeader}>
        <Text style={styles.sectionTitle}>틀린 기사 다시보기</Text>
        <Text style={styles.sectionSubtitle}>최근 1년의 기사를 확인하세요</Text>
      </View>

      <View style={styles.filterBar}>
        <FlatList
          data={categories}
          horizontal
          keyExtractor={(c) => c}
          showsHorizontalScrollIndicator={false}
          renderItem={({ item }) => (
            <TouchableOpacity
              style={[styles.categoryBtn, selectedCategory === item && styles.categoryBtnActive]}
              onPress={() => setSelectedCategory(item)}
            >
              <Text style={[styles.categoryText, selectedCategory === item && styles.categoryTextActive]}>
                {item}
              </Text>
            </TouchableOpacity>
          )}
        />

        <TouchableOpacity
          style={styles.sortBtn}
          onPress={() => setSortOrder((s) => (s === "newest" ? "oldest" : "newest"))}
        >
          <Ionicons name={sortOrder === "newest" ? "arrow-down" : "arrow-up"} size={18} color="#007AFF" />
          <Text style={styles.sortText}>{sortOrder === "newest" ? "최신순" : "오래된 순"}</Text>
        </TouchableOpacity>
      </View>
    </View>
  );

  // ---------------------------------------------------------
  // 리스트 아이템
  // ---------------------------------------------------------
  const renderItem = ({ item }: { item: HistoryItem }) => (
    <View style={styles.timelineItem}>
      <View style={styles.timelineLeft}>
        <View style={styles.line} />
        <View style={styles.dot} />
      </View>

      <View style={styles.timelineRight}>
        <Text style={styles.dateText}>{item.solvedAt}</Text>
        <TouchableOpacity
          style={styles.articleCard}
          onPress={() => router.push(`/article/${item.articleId}?retry=true`)}
        >
          <Text style={styles.articleTitle} numberOfLines={2}>{item.title}</Text>
          <Text style={styles.articleCategory}>{item.category}</Text>
        </TouchableOpacity>
      </View>
    </View>
  );

  // ---------------------------------------------------------
  // 메인 렌더링
  // ---------------------------------------------------------
  return (
    <View style={styles.container}>
      {isLoading ? (
        <View style={styles.loadingContainer}>
          <ActivityIndicator size="large" color="#4A8CFF" />
          <Text style={styles.loadingText}>정보를 불러오는 중...</Text>
        </View>
      ) : (
        <FlatList
          data={historyData
            .filter((h) => selectedCategory === "All" ? true : h.category === selectedCategory)
            .sort((a, b) => {
              const ad = new Date(a.solvedAt).getTime();
              const bd = new Date(b.solvedAt).getTime();
              return sortOrder === "newest" ? bd - ad : ad - bd;
            })}
          renderItem={renderItem}
          keyExtractor={(item) => item.articleId}
          ListHeaderComponent={renderHeader}
          contentContainerStyle={styles.listContentContainer}
          showsVerticalScrollIndicator={false}
          refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} />}
          ListEmptyComponent={
            <View style={styles.emptyContainer}>
              <Text style={styles.emptyText}>틀린 문제가 없습니다 🎉</Text>
            </View>
          }
        />
      )}
    </View>
  );
}


// -----------------------------------------------------
// 스타일 정의
// -----------------------------------------------------
const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#F5FAFF" }, // 전체 배경 기본 backgroundcolor와 동일하게
  
  // FlatList 내부 여백 (헤더 포함 전체 리스트)
  listContentContainer: {
    paddingBottom: 40,
  },

  // --- 1. 프로필 카드 스타일 ---
  headerSection: {
    paddingTop: 60, // 상태바 여백
    paddingHorizontal: 20,
    paddingBottom: 30,
    backgroundColor: "#F5FAFF", // 스크롤 시 위쪽 배경 흰색 유지
  },
  trendyCard: {
    flexDirection: "row",
    alignItems: "center",
    backgroundColor: "#ffffff",
    padding: 24,
    borderRadius: 24,
    // 그림자 강화
    ...Platform.select({
      ios: {
        shadowColor: "#000",
        shadowOffset: { width: 0, height: 8 },
        shadowOpacity: 0.08,
        shadowRadius: 12,
      },
      android: { elevation: 6 },
    }),
    borderWidth: 1,
    borderColor: "#F2F4F6",
  },
  profileLeft: { marginRight: 18 },
  trendyImage: {
    width: 72,
    height: 72,
    borderRadius: 36,
    backgroundColor: "#F2F4F6",
    borderWidth: 2,
    borderColor: "#fff",
  },
  profileRight: { flex: 1, justifyContent: "center" },
  nameRow: { flexDirection: "row", alignItems: "center", marginBottom: 6 },
  userName: { fontSize: 22, fontWeight: "800", color: "#1A1A1A", marginRight: 8 },
  userId: { fontSize: 14, color: "#8E8E93", fontWeight: "500" },

  // --- 2. 타임라인 헤더 (제목) ---
  timelineHeader: {
    paddingHorizontal: 24,
    paddingBottom: 10,
    backgroundColor: "#F5FAFF", // 리스트와 자연스럽게 연결
  },
  sectionTitle: { fontSize: 18, fontWeight: "700", color: "#1A1A1A", marginBottom: 6 },
  sectionSubtitle: { fontSize: 14, color: "#8E8E93", marginBottom: 20 },

  // 필터/정렬 바
  filterBar: { flexDirection: "row", alignItems: "center", justifyContent: "space-between", marginTop: 8 },
  categoryBtn: { paddingVertical: 6, paddingHorizontal: 12, backgroundColor: "#fff", borderRadius: 20, borderWidth: 1, borderColor: "#ECEFF5", marginRight: 8 },
  categoryBtnActive: { backgroundColor: "#007AFF", borderColor: "#007AFF" },
  categoryText: { fontSize: 13, color: "#333" },
  categoryTextActive: { color: "#fff", fontWeight: "700" },
  sortBtn: { flexDirection: "row", alignItems: "center", padding: 8, marginLeft: 8 },
  sortText: { marginLeft: 6, color: "#007AFF", fontWeight: "600" },

  // --- 3. 타임라인 아이템 (리스트 내부) ---
  timelineItem: {
    flexDirection: "row",
    paddingHorizontal: 24, // 리스트 좌우 여백
    marginBottom: 0,
  },
  timelineLeft: { width: 32, alignItems: "center", marginRight: 12 },
  line: { position: "absolute", top: 0, bottom: 0, width: 2, backgroundColor: "#E5E5EA" }, // 밝은 회색 줄
  dot: { 
    marginTop: 24, 
    width: 14, height: 14, borderRadius: 7, 
    backgroundColor: "#007AFF", 
    borderWidth: 3, borderColor: "#fff", 
    zIndex: 1 
  },
  timelineRight: { flex: 1, paddingBottom: 28 },
  dateText: { fontSize: 14, fontWeight: "600", color: "#8E8E93", marginBottom: 10 },
  articleCard: {
    backgroundColor: "#fff",
    borderRadius: 16,
    padding: 20,
    // 카드 그림자
    ...Platform.select({
      ios: {
        shadowColor: "#000",
        shadowOffset: { width: 0, height: 4 },
        shadowOpacity: 0.05,
        shadowRadius: 8,
      },
      android: { elevation: 2 },
    }),
    borderWidth: 1,
    borderColor: "#F2F4F6",
  },
  articleTitle: { fontSize: 15, fontWeight: "600", color: "#1A1A1A", marginBottom: 8, lineHeight: 24 },
  articleCategory: { fontSize: 13, fontWeight: "500", color: "#007AFF" },

  // 로딩 및 기타 스타일
  loadingContainer: { flex: 1, justifyContent: "center", alignItems: "center" },
  loadingText: { marginTop: 12, color: "#8E8E93", fontSize: 15 },
  emptyContainer: { alignItems: "center", marginTop: 60 },
  emptyText: { color: "#999", fontSize: 16 },

  // 모달 스타일
  modalOverlay: { flex: 1, backgroundColor: "rgba(0,0,0,0.5)", justifyContent: "center", alignItems: "center" },
  modalContent: { width: "85%", backgroundColor: "white", borderRadius: 20, padding: 28, alignItems: "center", elevation: 5 },
  modalTitle: { fontSize: 20, fontWeight: "bold", marginBottom: 20, color: "#1A1A1A" },
  input: { width: "100%", height: 52, borderWidth: 1, borderColor: "#E5E5EA", borderRadius: 12, paddingHorizontal: 16, marginBottom: 24, fontSize: 16, backgroundColor: "#F2F4F6" },
  modalButtons: { flexDirection: "row", width: "100%", gap: 12 },
  modalBtn: { flex: 1, paddingVertical: 14, borderRadius: 12, alignItems: "center", justifyContent: "center" },
  cancelBtn: { backgroundColor: "#F2F4F6" },
  saveBtn: { backgroundColor: "#007AFF" },
  cancelText: { fontSize: 16, color: "#8E8E93", fontWeight: "600" },
  saveText: { fontSize: 16, color: "white", fontWeight: "600" },
});

// import React, { useState, useEffect } from "react";
// import {
//   View,
//   Text,
//   Image,
//   TouchableOpacity,
//   StyleSheet,
//   Modal,
//   TextInput,
//   Alert,
//   FlatList,
//   ActivityIndicator,
//   RefreshControl,
//   Platform,
// } from "react-native";
// import { useRouter } from "expo-router";
// import { Ionicons } from "@expo/vector-icons"; 
// // import { apiClient } from "@/src/api/apiClient"; // (나중에 실제 연동 시 주석 해제)

// // ---------------------------------------------------------
// // 1. 데이터 타입 정의
// // ---------------------------------------------------------
// type UserProfile = {
//   nickname: string;
//   email: string;
//   profileImage: any;
// };

// type HistoryItem = {
//   article_id: number; // bigint는 JS에서 number나 string으로 처리됨
//   serving_date: string;
//   title: string;
//   category_name: string;
//   isWrong: boolean;
// };

// export default function MyPage() {
//   const router = useRouter();

//   // ---------------------------------------------------------
//   // 상태 관리 (State)
//   // ---------------------------------------------------------
//   const [userProfile, setUserProfile] = useState<UserProfile | null>(null);
//   const [historyData, setHistoryData] = useState<HistoryItem[]>([]);
//   const [isLoading, setIsLoading] = useState(true);
//   const [refreshing, setRefreshing] = useState(false);

//   const [modalVisible, setModalVisible] = useState(false);
//   const [inputText, setInputText] = useState("");

//   // ---------------------------------------------------------
//   // 데이터 통합 요청
//   // ---------------------------------------------------------
//   const fetchAllData = async () => {
//     try {
//       console.log("[Client] 유저 정보와 타임라인 데이터를 동시에 요청합니다...");
      
//       // 백엔드 응답 시간 시뮬레이션
//       await new Promise((resolve) => setTimeout(resolve, 1000));

//       const mockUser: UserProfile = {
//         nickname: "김제니",
//         email: "hwimin@kakao.com",
//         profileImage: require("../../../assets/knight/basic_profile.png"),
//       };

//       const mockHistory: HistoryItem[] = [
//         { article_id: 1, serving_date: "2025.03.10", title: "전기차 배터리 기술의 새로운 돌파구, 충전 시간 10분으로 단축", category_name: "Tech News", isWrong: true },
//         { article_id: 2, serving_date: "2025.03.08", title: "AI가 의료 진단 정확도 95%까지 향상시켰다", category_name: "Health Daily", isWrong: true },
//         { article_id: 3, serving_date: "2025.03.05", title: "“AI 에이전트는 아직 ‘말 없는 마차’ 수준…완전한 자율화는 먼 미래”", category_name: "Environment Weekly", isWrong: true },
//         { article_id: 4, serving_date: "2025.03.05", title: "AI 시대에도 ‘개방성’이 힘을 가질까?", category_name: "Environment Weekly", isWrong: true },
//         { article_id: 5, serving_date: "2025.03.03", title: "보안 행동과 인식 수준을 높이는 핵심 전략 ‘공감 기반 정책 엔지니어링’", category_name: "Environment Weekly", isWrong: true },
//       ];

//       setUserProfile(mockUser);
//       setHistoryData(mockHistory);

//     } catch (error) {
//       console.error("데이터 로딩 실패:", error);
//       Alert.alert("오류", "데이터를 불러오지 못했습니다.");
//     } finally {
//       setIsLoading(false);
//       setRefreshing(false);
//     }
//   };

//   useEffect(() => {
//     fetchAllData();
//   }, []);

//   const onRefresh = () => {
//     setRefreshing(true);
//     fetchAllData();
//   };

//   // ---------------------------------------------------------
//   // 닉네임 수정 로직
//   // ---------------------------------------------------------
//   const openEditModal = () => {
//     if (!userProfile) return;
//     setInputText(userProfile.nickname);
//     setModalVisible(true);
//   };

//   const handleSaveNickname = async () => {
//     if (inputText.trim() === "") {
//       Alert.alert("알림", "닉네임을 입력해주세요.");
//       return;
//     }
//     try {
//       console.log(`[서버 전송] 닉네임 변경 요청: ${inputText}`);
//       setUserProfile((prev) => prev ? { ...prev, nickname: inputText } : null);
//       setModalVisible(false);
//       Alert.alert("성공", "닉네임이 수정되었습니다.");
//     } catch (error) {
//       Alert.alert("오류", "닉네임 수정 실패");
//     }
//   };

//   // ---------------------------------------------------------
//   // 리스트 헤더 (프로필 + 제목)
//   // ---------------------------------------------------------
//   const renderHeader = () => {
//     if (!userProfile) return null;

//     return (
//       <View>
//         {/* 1. 프로필 카드 영역 */}
//         <View style={styles.headerSection}>
//           <TouchableOpacity style={styles.trendyCard} activeOpacity={0.9} onPress={openEditModal}>
//             <View style={styles.profileLeft}>
//               <Image source={userProfile.profileImage} style={styles.trendyImage} />
              
//               {/* 🍕 [추가] 프로필 이미지 위에 작은 피자 뱃지 포인트 */}
//               <View style={styles.pizzaBadge}>
//                 <Ionicons name="pizza" size={14} color="#fff" />
//               </View>
//             </View>

//             <View style={styles.profileRight}>
//               <View style={styles.nameRow}>
//                 <Text style={styles.userName}>{userProfile.nickname}</Text>
//                 {/* 🍕 [변경] 펜 아이콘을 피자색 포인트로 변경 */}
//                 <Ionicons name="pencil" size={16} color="#0a0a0aff" />
//               </View>
//               <Text style={styles.userId}>{userProfile.email}</Text>
//             </View>
//           </TouchableOpacity>
//         </View>

//         {/* 2. 타임라인 제목 영역 */}
//         <View style={styles.timelineHeader}>
//           <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 6 }}>
//             <Text style={styles.sectionTitle}>틀린 기사 다시보기</Text>
//           </View>
//           <Text style={styles.sectionSubtitle}>최근 1년의 기사를 최신순으로 확인하세요!</Text>
//         </View>
//       </View>
//     );
//   };

//   // ---------------------------------------------------------
//   // 리스트 아이템 (타임라인)
//   // ---------------------------------------------------------
//   const renderItem = ({ item }: { item: HistoryItem }) => (
//     <View style={styles.timelineItem}>
//       {/* 🍕 [변경] 왼쪽 라인 & 피자 아이콘 점 */}
//       <View style={styles.timelineLeft}>
//         <View style={styles.line} />
        
//         {/* 기존의 단순 dot 대신 피자 아이콘 사용 */}
//         <View style={styles.pizzaDotContainer}>
//           <Ionicons name="pizza" size={20} color="#007AFF" /> 
//         </View>
//       </View>

//       {/* 오른쪽 카드 내용 */}
//       <View style={styles.timelineRight}>
//         <Text style={styles.dateText}>{item.serving_date}</Text>
//         <TouchableOpacity 
//           style={styles.articleCard} 
//           onPress={() => router.push(`/article/${item.article_id}`)}
//         >
//           <Text style={styles.articleTitle} numberOfLines={2}>{item.title}</Text>
//           <View style={styles.categoryRow}>
//             <Text style={styles.articleCategory}>{item.category_name}</Text>
//           </View>
//         </TouchableOpacity>
//       </View>
//     </View>
//   );

//   // ---------------------------------------------------------
//   // 메인 렌더링
//   // ---------------------------------------------------------
//   return (
//     <View style={styles.container}>
//       {isLoading ? (
//         <View style={styles.loadingContainer}>
//           {/* 🍕 [변경] 로딩 스피너 색상을 피자 치즈/소스 색상으로 */}
//           <ActivityIndicator size="large" color="#FF6347" />
//           <Text style={styles.loadingText}>토핑 올리는 중...</Text>
//         </View>
//       ) : (
//         <FlatList
//           data={historyData}
//           renderItem={renderItem}
//           keyExtractor={(item) => item.article_id.toString()}
          
//           ListHeaderComponent={renderHeader}
          
//           contentContainerStyle={styles.listContentContainer}
//           showsVerticalScrollIndicator={false}
//           refreshControl={
//             // 🍕 [변경] 당겨서 새로고침 색상도 피자 컬러로
//             <RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor="#FF6347" colors={["#FF6347"]} />
//           }
//           ListEmptyComponent={
//             <View style={styles.emptyContainer}>
//               {/* 🍕 [추가] 데이터 없을 때 대왕 피자 아이콘 */}
//               <Ionicons name="pizza-outline" size={60} color="#ddd" style={{ marginBottom: 10 }} />
//               <Text style={styles.emptyText}>아직 틀린 문제가 없어요!</Text>
//               <Text style={styles.emptySubText}>맛있는 피자를 굽는 중... 🍕</Text>
//             </View>
//           }
//         />
//       )}

//       {/* 닉네임 수정 모달 */}
//       <Modal animationType="fade" transparent={true} visible={modalVisible} onRequestClose={() => setModalVisible(false)}>
//         <View style={styles.modalOverlay}>
//           <View style={styles.modalContent}>
//             {/* 🍕 [추가] 모달 제목 옆 아이콘 */}
//             <View style={{flexDirection: 'row', alignItems: 'center', marginBottom: 16}}>
//               <Text style={styles.modalTitle}>닉네임 수정</Text>
//               <Ionicons name="restaurant-outline" size={20} color="#333" style={{marginLeft: 8}}/>
//             </View>
            
//             <TextInput
//               style={styles.input}
//               value={inputText}
//               onChangeText={setInputText}
//               placeholder="새로운 닉네임을 입력하세요"
//               autoFocus={true}
//             />
//             <View style={styles.modalButtons}>
//               <TouchableOpacity style={[styles.modalBtn, styles.cancelBtn]} onPress={() => setModalVisible(false)}>
//                 <Text style={styles.cancelText}>취소</Text>
//               </TouchableOpacity>
//               <TouchableOpacity style={[styles.modalBtn, styles.saveBtn]} onPress={handleSaveNickname}>
//                 <Text style={styles.saveText}>저장</Text>
//               </TouchableOpacity>
//             </View>
//           </View>
//         </View>
//       </Modal>
//     </View>
//   );
// }

// // -----------------------------------------------------
// // 스타일 정의 (기존 스타일 유지 + Pizza 포인트 추가)
// // -----------------------------------------------------
// const styles = StyleSheet.create({
//   container: { flex: 1, backgroundColor: "#F5FAFF" },
  
//   listContentContainer: {
//     paddingBottom: 40,
//   },

//   // --- 1. 프로필 카드 ---
//   headerSection: {
//     paddingTop: 60,
//     paddingHorizontal: 20,
//     paddingBottom: 30,
//     backgroundColor: "#F5FAFF",
//   },
//   trendyCard: {
//     flexDirection: "row",
//     alignItems: "center",
//     backgroundColor: "#ffffff",
//     padding: 24,
//     borderRadius: 24,
//     ...Platform.select({
//       ios: {
//         shadowColor: "#000",
//         shadowOffset: { width: 0, height: 8 },
//         shadowOpacity: 0.08,
//         shadowRadius: 12,
//       },
//       android: { elevation: 6 },
//     }),
//     borderWidth: 1,
//     borderColor: "#F2F4F6",
//   },
//   profileLeft: { 
//     marginRight: 18,
//     position: 'relative', // 뱃지 위치 잡기 위해
//   },
//   trendyImage: {
//     width: 72,
//     height: 72,
//     borderRadius: 36,
//     backgroundColor: "#F2F4F6",
//     borderWidth: 2,
//     borderColor: "#fff",
//   },
//   // 🍕 피자 뱃지 스타일
//   pizzaBadge: {
//     position: 'absolute',
//     bottom: 0,
//     right: 0,
//     backgroundColor: '#007AFF', 
//     width: 24,
//     height: 24,
//     borderRadius: 12,
//     alignItems: 'center',
//     justifyContent: 'center',
//     borderWidth: 2,
//     borderColor: '#fff',
//   },
//   profileRight: { flex: 1, justifyContent: "center" },
//   nameRow: { flexDirection: "row", alignItems: "center", marginBottom: 6 },
//   userName: { fontSize: 22, fontWeight: "800", color: "#1A1A1A", marginRight: 8 },
//   userId: { fontSize: 14, color: "#8E8E93", fontWeight: "500" },

//   // --- 2. 타임라인 헤더 ---
//   timelineHeader: {
//     paddingHorizontal: 24,
//     paddingBottom: 10,
//     backgroundColor: "#F5FAFF",
//   },
//   sectionTitle: { fontSize: 18, fontWeight: "700", color: "#1A1A1A" }, // margin removed for row layout
//   sectionSubtitle: { fontSize: 14, color: "#8E8E93", marginBottom: 20 },

//   // --- 3. 타임라인 아이템 ---
//   timelineItem: {
//     flexDirection: "row",
//     paddingHorizontal: 24,
//     marginBottom: 0,
//   },
//   timelineLeft: { width: 32, alignItems: "center", marginRight: 12 },
//   line: { position: "absolute", top: 0, bottom: 0, width: 2, backgroundColor: "#E5E5EA" },
  
//   // 🍕 기존 dot 대신 아이콘 컨테이너
//   pizzaDotContainer: {
//     marginTop: 24,
//     width: 24, 
//     height: 24, 
//     alignItems: 'center',
//     justifyContent: 'center',
//     backgroundColor: '#F5FAFF', // 라인을 가리기 위한 배경색
//     zIndex: 1,
//   },
  
//   timelineRight: { flex: 1, paddingBottom: 28 },
//   dateText: { fontSize: 14, fontWeight: "600", color: "#8E8E93", marginBottom: 10 },
//   articleCard: {
//     backgroundColor: "#fff",
//     borderRadius: 16,
//     padding: 20,
//     ...Platform.select({
//       ios: {
//         shadowColor: "#000",
//         shadowOffset: { width: 0, height: 4 },
//         shadowOpacity: 0.05,
//         shadowRadius: 8,
//       },
//       android: { elevation: 2 },
//     }),
//     borderWidth: 1,
//     borderColor: "#F2F4F6",
//   },
//   articleTitle: { fontSize: 15, fontWeight: "600", color: "#1A1A1A", marginBottom: 8, lineHeight: 24 },
//   categoryRow: { flexDirection: 'row', alignItems: 'center' },
//   articleCategory: { fontSize: 13, fontWeight: "500", color: "#007AFF" },

//   // 로딩 및 빈 상태
//   loadingContainer: { flex: 1, justifyContent: "center", alignItems: "center" },
//   loadingText: { marginTop: 12, color: "#FF6347", fontSize: 15, fontWeight: "600" },
//   emptyContainer: { alignItems: "center", marginTop: 60 },
//   emptyText: { color: "#999", fontSize: 16, fontWeight: "bold" },
//   emptySubText: { color: "#bbb", fontSize: 14, marginTop: 4 },

//   // 모달 스타일
//   modalOverlay: { flex: 1, backgroundColor: "rgba(0,0,0,0.5)", justifyContent: "center", alignItems: "center" },
//   modalContent: { width: "85%", backgroundColor: "white", borderRadius: 20, padding: 28, alignItems: "center", elevation: 5 },
//   modalTitle: { fontSize: 20, fontWeight: "bold", color: "#1A1A1A" }, // marginBottom removed for row layout
//   input: { width: "100%", height: 52, borderWidth: 1, borderColor: "#E5E5EA", borderRadius: 12, paddingHorizontal: 16, marginBottom: 24, fontSize: 16, backgroundColor: "#F2F4F6" },
//   modalButtons: { flexDirection: "row", width: "100%", gap: 12 },
//   modalBtn: { flex: 1, paddingVertical: 14, borderRadius: 12, alignItems: "center", justifyContent: "center" },
//   cancelBtn: { backgroundColor: "#F2F4F6" },
//   saveBtn: { backgroundColor: "#FF6347" }, // 🍕 저장 버튼도 피자색
//   cancelText: { fontSize: 16, color: "#8E8E93", fontWeight: "600" },
//   saveText: { fontSize: 16, color: "white", fontWeight: "600" },
// });