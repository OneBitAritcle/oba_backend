import React, { useState, useEffect } from "react";
import { View, Text, StyleSheet, ActivityIndicator } from "react-native";
import { apiClient } from "../../../src/api/apiClient";
import { COLORS, RADIUS, SHADOWS, TYPO, SPACING } from "../../../constants/theme";

export interface CategoryData { categoryId?: number; category: string; progress: number; totalQuizzes?: number; correctQuizzes?: number; color?: string; }

const HIDDEN_CATEGORIES = ["Apple", "애플", "퍼스널 컴퓨팅", "PC", "apple", "퍼스널컴퓨팅"];

const SHORT_NAMES: Record<string, string> = {
  "인공지능": "AI", "생성형 AI": "생성AI", "클라우드 컴퓨팅": "클라우드",
  "데이터센터": "데이터센터", "생산성 소프트웨어": "생산성SW", "협업 소프트웨어": "협업SW", "증강 현실": "AR",
  "엔터프라이즈 애플리케이션": "엔터프라이즈", "소프트웨어 개발": "SW개발", "IT 리더십": "IT리더십",
  "기술 업계 동향": "기술동향", "IT 관리": "IT관리", "안드로이드": "안드로이드", "네트워크": "네트워크", "미래기술": "미래기술",
};

const WARM_PALETTE = [
  "#FF8C42", "#FFA96B", "#FFD54F", "#E74C3C", "#27AE60",
  "#F39C12", "#E67E22", "#D35400", "#C0392B", "#2ECC71",
  "#F1C40F", "#E88E5A", "#FF6B6B", "#48C9B0", "#AF7AC5",
  "#85C1E9", "#F7DC6F", "#EB984E", "#76D7C4", "#BB8FCE",
];

export default function CategoryProgress() {
  const [categories, setCategories] = useState<CategoryData[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<boolean>(false);

  useEffect(() => {
    const fetch = async () => {
      try {
        setLoading(true);
        const r = await apiClient.get("/api/report/category-progress");
        const filtered = (r.data as CategoryData[]).filter(
          (item) => !HIDDEN_CATEGORIES.some((h) => item.category.toLowerCase().includes(h.toLowerCase()))
        );
        const recalculated = filtered.map((item) => ({
          ...item,
          progress: item.totalQuizzes && item.totalQuizzes > 0
            ? Math.round((item.correctQuizzes ?? 0) / item.totalQuizzes * 100)
            : item.progress,
        }));
        setCategories(recalculated);
      } catch { setError(true); } finally { setLoading(false); }
    };
    fetch();
  }, []);

  if (loading) return <View style={[s.card, s.centerContent]}><ActivityIndicator size="large" color={COLORS.primary} /></View>;
  if (error) return <View style={[s.card, s.centerContent]}><Text style={{ ...TYPO.bodySm, color: COLORS.textTertiary }}>데이터를 불러오지 못했습니다.</Text></View>;
  if (categories.length === 0) return <View style={[s.card, s.centerContent]}><Text style={{ ...TYPO.bodySm, color: COLORS.textTertiary }}>아직 풀어본 카테고리가 없습니다.</Text></View>;

  return (
    <View style={s.card}>
      <Text style={s.title}>카테고리별 정답률</Text>
      <View style={s.listContainer}>
        {categories.map((item, index) => (
          <View key={index} style={s.categoryRow}>
            <Text style={s.categoryName} numberOfLines={1}>{SHORT_NAMES[item.category] || item.category}</Text>
            <View style={s.progressTrack}>
              <View style={[s.progressFill, { width: `${Math.min(item.progress, 100)}%`, backgroundColor: WARM_PALETTE[index % WARM_PALETTE.length] }]} />
            </View>
            <Text style={s.progressPercent}>{item.progress}%</Text>
          </View>
        ))}
      </View>
    </View>
  );
}

const s = StyleSheet.create({
  card: { backgroundColor: COLORS.bgCardElevated, borderRadius: RADIUS.card, padding: SPACING.xxl, marginHorizontal: SPACING.xl, marginVertical: SPACING.md, borderWidth: 1, borderColor: COLORS.glassBorder, ...SHADOWS.md, minHeight: 200 },
  centerContent: { justifyContent: "center", alignItems: "center" },
  title: { ...TYPO.h3, color: COLORS.textPrimary, marginBottom: SPACING.xxl },
  listContainer: { gap: SPACING.lg },
  categoryRow: { flexDirection: "row", alignItems: "center", justifyContent: "space-between" },
  categoryName: { width: 75, ...TYPO.caption, fontWeight: "600", color: COLORS.textSecondary },
  progressTrack: { flex: 1, height: 10, backgroundColor: COLORS.glass, borderRadius: 5, marginHorizontal: SPACING.md, overflow: "hidden" },
  progressFill: { height: "100%", borderRadius: 5 },
  progressPercent: { width: 36, ...TYPO.caption, fontWeight: "700", color: COLORS.textSecondary, textAlign: "right" },
});
