import React, { useEffect, useState } from "react";
import { View, Text, StyleSheet, ScrollView, ActivityIndicator, Pressable, StatusBar } from "react-native";
import { useRouter } from "expo-router";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { Ionicons } from "@expo/vector-icons";
import { apiClient } from "../../../src/api/apiClient";
import { useAuth } from "../../../src/auth/AuthContext";
import DailyChart from "../../components/report/DailyChart";
import CategoryProgress from "../../components/report/CategoryProgress";
import { COLORS, RADIUS, SHADOWS, TYPO, SPACING } from "../../../constants/theme";

interface ReportData {
  consecutiveDays: number; maxConsecutiveDays: number; perfectDays: number;
  solvedCount: number; totalCount: number;
  dailyStats: Array<{ day: string; learningRate?: number; accuracy: number }>;
  categoryProgress: Array<{ category: string; progress: number; color?: string }>;
}
const DEFAULT: ReportData = { consecutiveDays: 0, maxConsecutiveDays: 0, perfectDays: 0, solvedCount: 0, totalCount: 0, dailyStats: [], categoryProgress: [] };

const ReportStats = ({ consecutiveDays, maxConsecutiveDays, perfectDays }: { consecutiveDays: number; maxConsecutiveDays: number; perfectDays: number }) => (
  <View style={s.statsContainer}>
    {[{ v: consecutiveDays, l: "연속 학습일" }, { v: maxConsecutiveDays, l: "최고 기록" }, { v: perfectDays, l: "퍼펙트 데이" }].map((item, i) => (
      <View key={i} style={s.statCard}><Text style={s.statValue}>{item.v}</Text><Text style={s.statLabel}>{item.l}</Text></View>
    ))}
  </View>
);

const ProgressBar = ({ solvedCount, totalCount }: { solvedCount: number; totalCount: number }) => {
  const todayTotal = 5;
  const todaySolved = Math.min(solvedCount, todayTotal);
  const pct = (todaySolved / todayTotal) * 100;
  return (
    <View style={s.progressSection}>
      <View style={s.progressHeader}>
        <Text style={s.progressTitle}>오늘의 학습 진도</Text>
        <Text style={s.progressText}><Text style={s.highlightText}>{Math.round(pct)}%</Text> 달성</Text>
      </View>
      <View style={s.track}><View style={[s.fill, { width: `${pct}%` }]} /></View>
      <Text style={s.progressDetail}>오늘 기사 {todayTotal}개 중 {todaySolved}개 완료</Text>
    </View>
  );
};

export default function ReportPage() {
  const router = useRouter(); const insets = useSafeAreaInsets();
  const { isLoading: authLoading, isLoggedIn } = useAuth();
  const [reportData, setReportData] = useState<ReportData | null>(null); const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (authLoading) return;
    if (!isLoggedIn) { setReportData(DEFAULT); setLoading(false); return; }
    const fetch = async () => {
      try {
        setLoading(true); const data = { ...DEFAULT };
        const results = await Promise.allSettled([apiClient.get("/api/report/stats"), apiClient.get("/api/report/progress"), apiClient.get("/api/report/daily-stats?days=7"), apiClient.get("/api/report/category-progress")]);
        if (results[0].status === "fulfilled") { const d = results[0].value.data; data.consecutiveDays = d.consecutiveDays ?? 0; data.maxConsecutiveDays = d.maxConsecutiveDays ?? 0; data.perfectDays = d.perfectDays ?? 0; }
        if (results[1].status === "fulfilled") { const d = results[1].value.data; data.solvedCount = d.solvedCount ?? 0; data.totalCount = d.totalCount ?? 0; }
        if (results[2].status === "fulfilled") data.dailyStats = results[2].value.data ?? [];
        if (results[3].status === "fulfilled") data.categoryProgress = results[3].value.data ?? [];
        setReportData(data);
      } catch { setReportData(DEFAULT); } finally { setLoading(false); }
    };
    fetch();
  }, [authLoading]);

  if (loading) return <View style={[s.loadingContainer, { paddingTop: insets.top }]}><ActivityIndicator size="large" color={COLORS.primary} /></View>;
  if (!reportData) return null;

  return (
    <View style={s.screen}>
      <StatusBar barStyle="light-content" backgroundColor="transparent" />
      <View style={[s.header, { paddingTop: insets.top + 10 }]}>
        <Pressable onPress={() => router.push("/(tabs)")} style={s.backButton}><Ionicons name="chevron-back" size={24} color={COLORS.textPrimary} /></Pressable>
        <View style={s.headerTitleContainer}><Text style={s.headerTitle}>마이 리포트</Text><Text style={s.headerSubtitle}>나의 학습 기록을 분석해드려요</Text></View>
        <View style={{ width: 40 }} />
      </View>
      <ScrollView style={s.scrollView} contentContainerStyle={s.scrollContent} showsVerticalScrollIndicator={false}>
        <ReportStats consecutiveDays={reportData.consecutiveDays} maxConsecutiveDays={reportData.maxConsecutiveDays} perfectDays={reportData.perfectDays} />
        <ProgressBar solvedCount={reportData.solvedCount} totalCount={reportData.totalCount} />
        <DailyChart />
        <CategoryProgress />
        <View style={{ height: 40 }} />
      </ScrollView>
    </View>
  );
}

const s = StyleSheet.create({
  screen: { flex: 1, backgroundColor: COLORS.bgPrimary },
  loadingContainer: { flex: 1, justifyContent: "center", alignItems: "center" },
  header: { flexDirection: "row", alignItems: "center", justifyContent: "space-between", paddingHorizontal: SPACING.xl, paddingBottom: SPACING.xl },
  backButton: { width: 40, height: 40, justifyContent: "center", alignItems: "flex-start" },
  headerTitleContainer: { alignItems: "center" },
  headerTitle: { ...TYPO.h3, color: COLORS.textPrimary },
  headerSubtitle: { ...TYPO.caption, color: COLORS.textTertiary, marginTop: 2 },
  scrollView: { flex: 1 },
  scrollContent: { paddingBottom: 40 },
  statsContainer: { flexDirection: "row", justifyContent: "space-between", paddingHorizontal: SPACING.xl, marginBottom: SPACING.xxl, gap: SPACING.md },
  statCard: { flex: 1, backgroundColor: COLORS.bgCardElevated, borderRadius: RADIUS.card, paddingVertical: SPACING.lg, alignItems: "center", justifyContent: "center", borderWidth: 1, borderColor: COLORS.glassBorder, ...SHADOWS.md },
  statValue: { fontSize: 24, fontWeight: "800", color: COLORS.primaryLight, marginBottom: 4 },
  statLabel: { ...TYPO.caption, color: COLORS.textTertiary },
  progressSection: { marginHorizontal: SPACING.xl, marginBottom: SPACING.md, backgroundColor: COLORS.bgCardElevated, borderRadius: RADIUS.card, padding: SPACING.xxl, borderWidth: 1, borderColor: COLORS.glassBorder, ...SHADOWS.md },
  progressHeader: { flexDirection: "row", justifyContent: "space-between", alignItems: "flex-end", marginBottom: SPACING.md },
  progressTitle: { ...TYPO.label, color: COLORS.textPrimary },
  progressText: { ...TYPO.caption, color: COLORS.textTertiary },
  highlightText: { ...TYPO.button, color: COLORS.primaryLight },
  track: { height: 10, backgroundColor: COLORS.glass, borderRadius: 5, overflow: "hidden", marginBottom: SPACING.sm },
  fill: { height: "100%", backgroundColor: COLORS.primary, borderRadius: 5 },
  progressDetail: { ...TYPO.caption, color: COLORS.textPlaceholder, textAlign: "right" },
});
