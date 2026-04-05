import React, { useEffect, useState } from "react";
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  ActivityIndicator,
  Pressable,
  StatusBar,
} from "react-native";
import { useRouter } from "expo-router";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { Ionicons } from "@expo/vector-icons";
import { apiClient } from "../../../src/api/apiClient";
import { useAuth } from "../../../src/auth/AuthContext";

// 컴포넌트 임포트
import DailyChart from "../../components/report/DailyChart";
import CategoryProgress from "../../components/report/CategoryProgress";

/**
 * ========================================================
 * 📊 학습 리포트 페이지 (Report Page)
 * ========================================================
 * 
 * 📍 API 명세 문서: /BACKEND_API_SPEC.md
 * 
 * 필요한 API 엔드포인트:
 * 1. GET /api/report/stats               → ReportStats (통계 카드)
 * 2. GET /api/report/progress            → ProgressBar (진도바)
 * 3. GET /api/report/daily-stats         → DailyChart (요일별 정답률)
 * 4. GET /api/report/category-progress   → CategoryProgress (카테고리별 정답률)
 * 
 * 🚀 백엔드 준비 완료 후 로직:
 * - fetchReportData() 함수에서 실제 API 호출로 변경
 * - DUMMY_REPORT_DATA 대신 response 데이터 사용
 */

// 📌 [Types & Interfaces]
interface ReportData {
  consecutiveDays: number;
  maxConsecutiveDays: number;
  perfectDays: number;
  solvedCount: number;
  totalCount: number;
  // DailyChart가 사용하는 데이터 구조와 일치해야 함
  dailyStats: Array<{ day: string; learningRate?: number; accuracy: number }>;
  // CategoryProgress가 사용하는 데이터 구조와 일치해야 함
  categoryProgress: Array<{ category: string; progress: number; color?: string }>;
}

// 📌 [Dummy Data]
const DEFAULT_REPORT_DATA: ReportData = {
  consecutiveDays: 0,
  maxConsecutiveDays: 0,
  perfectDays: 0,
  solvedCount: 0,
  totalCount: 0,
  dailyStats: [],
  categoryProgress: [],
};

// 📌 [Sub Components for Page Layout]

/**
 * 1. 통계 요약 카드 (상단 3개)
 */
const ReportStats = ({
  consecutiveDays,
  maxConsecutiveDays,
  perfectDays,
}: {
  consecutiveDays: number;
  maxConsecutiveDays: number;
  perfectDays: number;
}) => {
  return (
    <View style={styles.statsContainer}>
      <View style={styles.statCard}>
        <Text style={styles.statValue}>{consecutiveDays}</Text>
        <Text style={styles.statLabel}>연속 학습일</Text>
      </View>
      <View style={styles.statCard}>
        <Text style={styles.statValue}>{maxConsecutiveDays}</Text>
        <Text style={styles.statLabel}>최고 기록</Text>
      </View>
      <View style={styles.statCard}>
        <Text style={styles.statValue}>{perfectDays}</Text>
        <Text style={styles.statLabel}>퍼펙트 데이</Text>
      </View>
    </View>
  );
};

/**
 * 2. 전체 진도율 (Progress Bar)
 */
const ProgressBar = ({
  solvedCount,
  totalCount,
}: {
  solvedCount: number;
  totalCount: number;
}) => {
  const percentage = totalCount > 0 ? (solvedCount / totalCount) * 100 : 0;
  
  return (
    <View style={styles.progressSection}>
      <View style={styles.progressHeader}>
        <Text style={styles.progressTitle}>전체 학습 진도</Text>
        <Text style={styles.progressText}>
          <Text style={styles.highlightText}>{Math.round(percentage)}%</Text> 달성
        </Text>
      </View>
      
      <View style={styles.track}>
        <View style={[styles.fill, { width: `${percentage}%` }]} />
      </View>
      
      <Text style={styles.progressDetail}>
        총 {totalCount}개 중 {solvedCount}개 완료
      </Text>
    </View>
  );
};

// 📌 [Main Page Component]
export default function ReportPage() {
  const router = useRouter();
  const insets = useSafeAreaInsets();
  const { isLoading: authLoading, isLoggedIn } = useAuth();
  const [reportData, setReportData] = useState<ReportData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (authLoading) return;
    if (!isLoggedIn) {
      setReportData(DEFAULT_REPORT_DATA);
      setLoading(false);
      return;
    }
    /**
     * 📌 리포트 데이터 로드 함수
     * 
     * ✅ 중요사항:
     * - 모든 API는 JWT 토큰에서 user_id를 자동으로 추출
     * - Query Parameter로 user_id를 전달하지 않음
     * - Authorization 헤더는 apiClient에서 자동으로 추가
     * 
     * 🚀 API 연동 방법 (주석 해제하여 사용):
     * 
     * import { apiClient } from "../../src/api/apiClient";
     * 
     * const [statsRes, progressRes, dailyRes, categoryRes] = await Promise.all([
     *   apiClient.get("/api/report/stats"),              // user_id 자동 추출
     *   apiClient.get("/api/report/progress"),          // user_id 자동 추출
     *   apiClient.get("/api/report/daily-stats?days=7"), // user_id 자동 추출 + days 전달
     *   apiClient.get("/api/report/category-progress"),  // user_id 자동 추출
     * ]);
     * 
     * setReportData({
     *   consecutiveDays: statsRes.data.consecutiveDays,
     *   maxConsecutiveDays: statsRes.data.maxConsecutiveDays,
     *   perfectDays: statsRes.data.perfectDays,
     *   solvedCount: progressRes.data.solvedCount,
     *   totalCount: progressRes.data.totalCount,
     *   dailyStats: dailyRes.data,
     *   categoryProgress: categoryRes.data,
     * });
     */
    
    const fetchReportData = async () => {
      try {
        setLoading(true);
        const data = { ...DEFAULT_REPORT_DATA };

        const results = await Promise.allSettled([
          apiClient.get("/api/report/stats"),
          apiClient.get("/api/report/progress"),
          apiClient.get("/api/report/daily-stats?days=7"),
          apiClient.get("/api/report/category-progress"),
        ]);

        results.forEach((r, i) => {
          if (r.status === "rejected") {
            console.error(`[Report] API ${i} failed:`, r.reason?.response?.status, r.reason?.message);
          }
        });

        if (results[0].status === "fulfilled") {
          const d = results[0].value.data;
          data.consecutiveDays = d.consecutiveDays ?? 0;
          data.maxConsecutiveDays = d.maxConsecutiveDays ?? 0;
          data.perfectDays = d.perfectDays ?? 0;
        }
        if (results[1].status === "fulfilled") {
          const d = results[1].value.data;
          data.solvedCount = d.solvedCount ?? 0;
          data.totalCount = d.totalCount ?? 0;
        }
        if (results[2].status === "fulfilled") {
          data.dailyStats = results[2].value.data ?? [];
        }
        if (results[3].status === "fulfilled") {
          data.categoryProgress = results[3].value.data ?? [];
        }

        setReportData(data);
      } catch (error) {
        console.error("[Report] 데이터 로드 실패:", error);
        setReportData(DEFAULT_REPORT_DATA);
      } finally {
        setLoading(false);
      }
    };
    fetchReportData();
  }, [authLoading]);

  if (loading) {
    return (
      <View style={[styles.loadingContainer, { paddingTop: insets.top }]}>
        <ActivityIndicator size="large" color="#87CEEB" />
      </View>
    );
  }

  if (!reportData) return null;

  return (
    <View style={styles.screen}>
      <StatusBar barStyle="dark-content" backgroundColor="#F8F9FA" />
      
      {/* 1. 커스텀 헤더 */}
      <View style={[styles.header, { paddingTop: insets.top + 10 }]}>
        <Pressable onPress={() => router.push("/(tabs)")} style={styles.backButton}>
          <Ionicons name="chevron-back" size={24} color="#333" />
        </Pressable>
        <View style={styles.headerTitleContainer}>
          <Text style={styles.headerTitle}>마이 리포트</Text>
          <Text style={styles.headerSubtitle}>나의 학습 기록을 분석해드려요</Text>
        </View>
        <View style={{ width: 40 }} /> {/* 균형 맞추기용 빈 뷰 */}
      </View>

      <ScrollView
        style={styles.scrollView}
        contentContainerStyle={styles.scrollContent}
        showsVerticalScrollIndicator={false}
      >
        {/* 2. 상단 통계 카드 */}
        <ReportStats
          consecutiveDays={reportData.consecutiveDays}
          maxConsecutiveDays={reportData.maxConsecutiveDays}
          perfectDays={reportData.perfectDays}
        />

        {/* 3. 전체 진도율 */}
        <ProgressBar
          solvedCount={reportData.solvedCount}
          totalCount={reportData.totalCount}
        />

        {/* 4. 학습 성장 곡선 (외부 컴포넌트) */}
        {/* 
          🚀 DailyChart 컴포넌트
          - 📍 API 엔드포인트: GET /api/report/daily-stats
          - 현재: 내부적으로 Dummy 데이터 및 API 호출 시뮬레이션 (DailyChart.tsx 참고)
          - 향후: 부모에서 props로 전달하도록 리팩토링 권장
          - 참고 명세: /BACKEND_API_SPEC.md - "3️⃣ 요일별 정답률 조회"
        */}
        <DailyChart /> 

        {/* 5. 카테고리별 정답률 (외부 컴포넌트) */}
        {/* 
          🚀 CategoryProgress 컴포넌트
          - 📍 API 엔드포인트: GET /api/report/category-progress
          - 현재: 내부적으로 Dummy 데이터 및 API 호출 시뮬레이션 (CategoryProgress.tsx 참고)
          - 향후: 부모에서 props로 전달하도록 리팩토링 권장
          - 참고 명세: /BACKEND_API_SPEC.md - "4️⃣ 카테고리별 정답률 조회"
        */}
        <CategoryProgress />
        
        {/* 하단 여백 */}
        <View style={{ height: 40 }} />
      </ScrollView>
    </View>
  );
}

// 📌 [Styles]
const styles = StyleSheet.create({
  screen: {
    flex: 1,
    backgroundColor: "#F8F9FA", // 배경색: 아주 연한 회색 (눈이 편안함)
  },
  loadingContainer: {
    flex: 1,
    justifyContent: "center",
    alignItems: "center",
    backgroundColor: "#F8F9FA",
  },
  
  // Header
  header: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    paddingHorizontal: 20,
    paddingBottom: 20,
    backgroundColor: "#F8F9FA",
    // zIndex: 1,
  },
  backButton: {
    width: 40,
    height: 40,
    justifyContent: "center",
    alignItems: "flex-start",
    // backgroundColor: "#fff",
    // borderRadius: 20,
    // ...Platform.select({
    //   ios: { shadowColor: "#000", shadowOpacity: 0.1, shadowRadius: 4 },
    //   android: { elevation: 2 },
    // }),
    // paddingLeft: 8,
  },
  headerTitleContainer: {
    alignItems: "center",
  },
  headerTitle: {
    fontSize: 18,
    fontWeight: "bold",
    color: "#222",
  },
  headerSubtitle: {
    fontSize: 12,
    color: "#888",
    marginTop: 2,
  },

  // ScrollView
  scrollView: {
    flex: 1,
  },
  scrollContent: {
    paddingBottom: 40,
  },

  // 1. Stats Cards
  statsContainer: {
    flexDirection: "row",
    justifyContent: "space-between",
    paddingHorizontal: 20,
    marginBottom: 24,
    gap: 12,
  },
  statCard: {
    flex: 1,
    backgroundColor: "#fff",
    borderRadius: 16,
    paddingVertical: 16,
    alignItems: "center",
    justifyContent: "center",
    // Soft Shadow
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.05,
    shadowRadius: 8,
    elevation: 2,
  },
  statValue: {
    fontSize: 22,
    fontWeight: "800",
    color: "#333",
    marginBottom: 4,
  },
  statLabel: {
    fontSize: 12,
    fontWeight: "500",
    color: "#888",
  },

  // 2. Progress Bar Section
  progressSection: {
    marginHorizontal: 20,
    marginBottom: 12, // DailyChart와의 간격 (DailyChart marginVertical 고려)
    backgroundColor: "#fff",
    borderRadius: 20,
    padding: 24,
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.05,
    shadowRadius: 8,
    elevation: 2,
  },
  progressHeader: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "flex-end",
    marginBottom: 12,
  },
  progressTitle: {
    fontSize: 16,
    fontWeight: "bold",
    color: "#222",
  },
  progressText: {
    fontSize: 13,
    color: "#666",
  },
  highlightText: {
    fontWeight: "bold",
    color: "#87CEEB", // 포인트 컬러
    fontSize: 16,
  },
  track: {
    height: 10,
    backgroundColor: "#F0F0F0",
    borderRadius: 5,
    overflow: "hidden",
    marginBottom: 8,
  },
  fill: {
    height: "100%",
    backgroundColor: "#87CEEB",
    borderRadius: 5,
  },
  progressDetail: {
    fontSize: 12,
    color: "#AAA",
    textAlign: "right",
  },
});