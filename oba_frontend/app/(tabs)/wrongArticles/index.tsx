import React, { useState, useEffect } from "react";
import { View, Text, TouchableOpacity, StyleSheet, Alert, FlatList, ActivityIndicator, RefreshControl } from "react-native";
import { useRouter } from "expo-router";
import { Ionicons } from "@expo/vector-icons";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { apiClient } from "../../../src/api/apiClient";
import { COLORS, RADIUS, SHADOWS, TYPO, SPACING } from "../../../constants/theme";

type HistoryItem = { articleId: string; title: string; summary: string; imageUrl: string; category: string; solvedAt: string; };

export default function WrongArticlesPage() {
  const router = useRouter(); const insets = useSafeAreaInsets();
  const [historyData, setHistoryData] = useState<HistoryItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [selectedCategory, setSelectedCategory] = useState<string>("All");
  const [categories, setCategories] = useState<string[]>([]);
  const [sortOrder, setSortOrder] = useState<"newest" | "oldest">("newest");

  const fetchHistory = async () => {
    try { const res = await apiClient.get("/api/my/wrong"); setHistoryData(res.data); const cats = Array.from(new Set(res.data.map((h: HistoryItem) => h.category))); setCategories(["All", ...(cats as string[])]); }
    catch { Alert.alert("오류", "데이터를 불러오지 못했습니다."); } finally { setIsLoading(false); setRefreshing(false); }
  };
  useEffect(() => { fetchHistory(); }, []);
  const onRefresh = () => { setRefreshing(true); fetchHistory(); };

  const renderHeader = () => (
    <View style={[s.headerSection, { paddingTop: insets.top + 10 }]}>
      <TouchableOpacity onPress={() => router.push("/(tabs)")} style={s.backRow}><Ionicons name="chevron-back" size={24} color={COLORS.textPrimary} /><Text style={s.backText}>홈</Text></TouchableOpacity>
      <View style={s.titleBlock}><Text style={s.pageTitle}>틀린 기사 다시보기</Text><Text style={s.pageSubtitle}>최근 1년의 기사를 확인하세요</Text></View>
      <View style={s.filterBar}>
        <FlatList data={categories} horizontal keyExtractor={(c) => c} showsHorizontalScrollIndicator={false}
          renderItem={({ item }) => (
            <TouchableOpacity style={[s.chip, selectedCategory === item && s.chipActive]} onPress={() => setSelectedCategory(item)}>
              <Text style={[s.chipText, selectedCategory === item && s.chipTextActive]}>{item}</Text>
            </TouchableOpacity>
          )} />
        <TouchableOpacity style={s.sortBtn} onPress={() => setSortOrder((o) => (o === "newest" ? "oldest" : "newest"))}>
          <Ionicons name={sortOrder === "newest" ? "arrow-down" : "arrow-up"} size={18} color={COLORS.primaryLight} />
          <Text style={s.sortText}>{sortOrder === "newest" ? "최신순" : "오래된 순"}</Text>
        </TouchableOpacity>
      </View>
    </View>
  );

  const renderItem = ({ item }: { item: HistoryItem }) => (
    <View style={s.timelineItem}>
      <View style={s.timelineLeft}><View style={s.line} /><View style={s.dot} /></View>
      <View style={s.timelineRight}>
        <Text style={s.dateText}>{item.solvedAt}</Text>
        <TouchableOpacity style={s.articleCard} onPress={() => router.push(`/article/${item.articleId}?retry=true`)}>
          <Text style={s.articleTitle} numberOfLines={2}>{item.title}</Text>
          <Text style={s.articleCategory}>{item.category}</Text>
        </TouchableOpacity>
      </View>
    </View>
  );

  if (isLoading) return <View style={[s.loadingContainer, { paddingTop: insets.top }]}><ActivityIndicator size="large" color={COLORS.primary} /><Text style={s.loadingText}>정보를 불러오는 중...</Text></View>;

  return (
    <View style={s.screen}>
      <FlatList
        data={historyData.filter((h) => selectedCategory === "All" || h.category === selectedCategory).sort((a, b) => { const ad = new Date(a.solvedAt).getTime(); const bd = new Date(b.solvedAt).getTime(); return sortOrder === "newest" ? bd - ad : ad - bd; })}
        renderItem={renderItem} keyExtractor={(item) => item.articleId} ListHeaderComponent={renderHeader}
        contentContainerStyle={s.listContent} showsVerticalScrollIndicator={false}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor={COLORS.primary} colors={[COLORS.primary]} />}
        ListEmptyComponent={<View style={s.emptyContainer}><Text style={s.emptyText}>틀린 문제가 없습니다</Text></View>}
      />
    </View>
  );
}

const s = StyleSheet.create({
  screen: { flex: 1, backgroundColor: COLORS.bgPrimary },
  loadingContainer: { flex: 1, justifyContent: "center", alignItems: "center" },
  loadingText: { marginTop: SPACING.md, ...TYPO.bodySm, color: COLORS.textTertiary },
  listContent: { paddingBottom: 40 },
  headerSection: { paddingHorizontal: SPACING.xl, paddingBottom: SPACING.xxl },
  backRow: { flexDirection: "row", alignItems: "center", marginBottom: SPACING.lg },
  backText: { ...TYPO.label, color: COLORS.textPrimary, marginLeft: 2 },
  titleBlock: { marginBottom: SPACING.lg },
  pageTitle: { ...TYPO.h1, color: COLORS.textPrimary, marginBottom: 4 },
  pageSubtitle: { ...TYPO.bodySm, color: COLORS.textTertiary },
  filterBar: { flexDirection: "row", alignItems: "center", justifyContent: "space-between", marginTop: SPACING.sm },
  chip: { paddingVertical: 6, paddingHorizontal: 14, backgroundColor: COLORS.glass, borderRadius: RADIUS.pill, borderWidth: 1, borderColor: COLORS.glassBorder, marginRight: SPACING.sm },
  chipActive: { backgroundColor: COLORS.primary, borderColor: COLORS.primary },
  chipText: { ...TYPO.caption, color: COLORS.textSecondary },
  chipTextActive: { ...TYPO.caption, color: "#FFFFFF", fontWeight: "700" },
  sortBtn: { flexDirection: "row", alignItems: "center", padding: SPACING.sm, marginLeft: SPACING.sm },
  sortText: { marginLeft: 6, ...TYPO.caption, color: COLORS.primaryLight, fontWeight: "600" },
  timelineItem: { flexDirection: "row", paddingHorizontal: SPACING.xxl },
  timelineLeft: { width: 32, alignItems: "center", marginRight: SPACING.md },
  line: { position: "absolute", top: 0, bottom: 0, width: 2, backgroundColor: COLORS.glassBorder },
  dot: { marginTop: 24, width: 14, height: 14, borderRadius: 7, backgroundColor: COLORS.primary, borderWidth: 3, borderColor: COLORS.bgPrimary, zIndex: 1 },
  timelineRight: { flex: 1, paddingBottom: 28 },
  dateText: { ...TYPO.label, color: COLORS.textTertiary, marginBottom: SPACING.sm },
  articleCard: { backgroundColor: COLORS.bgCardElevated, borderRadius: RADIUS.lg, padding: SPACING.xl, borderWidth: 1, borderColor: COLORS.glassBorder, ...SHADOWS.sm },
  articleTitle: { ...TYPO.label, color: COLORS.textPrimary, marginBottom: SPACING.sm, lineHeight: 22 },
  articleCategory: { ...TYPO.caption, fontWeight: "600", color: COLORS.primaryLight },
  emptyContainer: { alignItems: "center", marginTop: 60 },
  emptyText: { ...TYPO.body, color: COLORS.textTertiary },
});
