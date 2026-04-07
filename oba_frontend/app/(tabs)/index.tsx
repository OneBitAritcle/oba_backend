import { useRef, useState, useEffect } from "react";
import {
  View, Text, Image, Animated, useWindowDimensions, Pressable,
  ActivityIndicator, StyleSheet,
} from "react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { Link } from "expo-router";
import AsyncStorage from "@react-native-async-storage/async-storage";
import { apiClient } from "../../src/api/apiClient";
import PizzaMenu from "../components/PizzaMenu";
import HomeHeader from "../components/HomeHeader";
import { COLORS, SHADOWS, TYPO, SPACING, RADIUS } from "../../constants/theme";

interface ArticleSummary {
  articleId: string; title: string; summaryBullets?: string[];
  thumbnailUrl?: string; servingDate?: string;
}
interface UserProfile { nickname: string; profileImage: string; }

function extractImageFromContent(content: string[]): string | null {
  if (!content) return null;
  for (const line of content) { if (line.startsWith("<img>")) return line.replace("<img>", ""); }
  return null;
}

export default function Home() {
  const insets = useSafeAreaInsets();
  const { width, height } = useWindowDimensions();
  const scrollX = useRef(new Animated.Value(0)).current;

  const CARD_WIDTH = width * 0.82;
  const CARD_HEIGHT = Math.min(height * 0.48, 460);
  const SIDE_SPACING = (width - CARD_WIDTH) / 2;
  const SNAP_INTERVAL = CARD_WIDTH + 14;

  const [articles, setArticles] = useState<ArticleSummary[]>([]);
  const [userProfile, setUserProfile] = useState<UserProfile | null>(null);
  const [streak, setStreak] = useState(0);
  const [daySliceCounts, setDaySliceCounts] = useState<number[]>([0, 0, 0, 0, 0, 0, 0]);
  const [loading, setLoading] = useState(true);

  const getFormattedDate = () => {
    const now = new Date();
    const days = ["일", "월", "화", "수", "목", "금", "토"];
    return `${now.getFullYear()}. ${String(now.getMonth() + 1).padStart(2, "0")}. ${String(now.getDate()).padStart(2, "0")}. (${days[now.getDay()]})`;
  };

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        try {
          const articlesRes = await apiClient.get("/api/articles/latest?limit=10");
          const data = articlesRes.data;
          let articleList: ArticleSummary[] = Array.isArray(data) ? data : [];
          const today = new Date().toISOString().split("T")[0];
          const todayArticles = articleList.filter((a) => a.servingDate === today);
          articleList = todayArticles.length > 0 ? todayArticles.slice(0, 5) : articleList.slice(0, 5);
          const articlesWithImages = await Promise.all(
            articleList.map(async (article) => {
              try {
                const detailRes = await apiClient.get(`/api/articles/${article.articleId}`);
                const imageUrl = extractImageFromContent(detailRes.data.content);
                return { ...article, thumbnailUrl: imageUrl || undefined };
              } catch { return article; }
            })
          );
          setArticles(articlesWithImages);
        } catch { setArticles([]); }
        try {
          const profileRes = await apiClient.get("/api/users/me");
          const nickname = profileRes.data.nickname || profileRes.data.displayName || profileRes.data.name || "한입기사님";
          const picture = profileRes.data.picture || "";
          setUserProfile({ nickname, profileImage: picture });
          setStreak(profileRes.data.consecutiveDays || 0);
          const weeklyLog = profileRes.data.weeklyLog || [];
          setDaySliceCounts(weeklyLog.map((v: boolean) => (v ? 1 : 0)));
          try { await AsyncStorage.setItem("oba_cached_profile", JSON.stringify({ nickname, picture })); } catch {}
        } catch {
          try {
            const cached = await AsyncStorage.getItem("oba_cached_profile");
            if (cached) { const p = JSON.parse(cached); setUserProfile({ nickname: p.nickname, profileImage: p.picture || "" }); }
            else { setUserProfile({ nickname: "한입기사님", profileImage: "" }); }
          } catch { setUserProfile({ nickname: "한입기사님", profileImage: "" }); }
        }
      } finally { setLoading(false); }
    };
    fetchData();
  }, []);

  if (loading) {
    return (
      <View style={[s.loadingContainer, { paddingTop: insets.top }]}>
        <ActivityIndicator size="large" color={COLORS.primary} />
        <Text style={s.loadingText}>기사를 불러오는 중...</Text>
      </View>
    );
  }

  return (
    <View style={[s.screen, { paddingTop: insets.top + 10 }]}>
      {userProfile && (
        <HomeHeader user={userProfile} streak={streak} date={getFormattedDate()} daySliceCounts={daySliceCounts} />
      )}

      <View style={{ flex: 1 }}>
        <View style={s.sectionHeader}>
          <Text style={s.sectionTitle}>오늘의 기사</Text>
          <Text style={s.sectionSub}>{articles.length}개의 기사를 확인하세요</Text>
        </View>

        {articles.length === 0 ? (
          <View style={s.emptyContainer}>
            <Image source={require("../../assets/knight/hand.png")} style={s.emptyImage} resizeMode="contain" />
            <Text style={s.emptyTitle}>아직 도착한 기사가 없어요.</Text>
            <Text style={s.emptyDate}>({new Date().toLocaleDateString()} 기준)</Text>
          </View>
        ) : (
          <Animated.ScrollView
            horizontal showsHorizontalScrollIndicator={false}
            snapToOffsets={articles.map((_, i) => i * SNAP_INTERVAL)}
            snapToAlignment="start" decelerationRate="fast" disableIntervalMomentum
            scrollEventThrottle={16}
            contentContainerStyle={{ paddingHorizontal: SIDE_SPACING }}
            onScroll={Animated.event([{ nativeEvent: { contentOffset: { x: scrollX } } }], { useNativeDriver: true })}
          >
            {articles.map((item, i) => {
              const inputRange = [(i - 1) * SNAP_INTERVAL, i * SNAP_INTERVAL, (i + 1) * SNAP_INTERVAL];
              const scale = scrollX.interpolate({ inputRange, outputRange: [0.93, 1, 0.93], extrapolate: "clamp" });
              const opacity = scrollX.interpolate({ inputRange, outputRange: [0.5, 1, 0.5], extrapolate: "clamp" });
              const summaryText = item.summaryBullets && item.summaryBullets.length > 0
                ? item.summaryBullets.slice(0, 3).map(b => `• ${b}`).join("\n") : "";

              return (
                <Link key={i} href={`/article/${item.articleId}`} asChild>
                  <Pressable>
                    <Animated.View style={[s.card, {
                      width: CARD_WIDTH, height: CARD_HEIGHT,
                      transform: [{ scale }], opacity,
                    }]}>
                      <View style={s.cardImageWrapper}>
                        <Image
                          source={item.thumbnailUrl ? { uri: item.thumbnailUrl } : require("../../assets/knight/deliever.png")}
                          style={s.cardImage} resizeMode="cover"
                        />
                        <View style={s.cardBadge}>
                          <Text style={s.cardBadgeText}>{i + 1} / {articles.length}</Text>
                        </View>
                      </View>
                      <View style={s.cardContent}>
                        <Text style={s.cardTitle} numberOfLines={2}>{item.title}</Text>
                        {summaryText ? (
                          <Text style={s.cardSummary} numberOfLines={3}>{summaryText}</Text>
                        ) : null}
                        <View style={s.cardFooter}>
                          <Text style={s.cardReadBtn}>읽기 →</Text>
                        </View>
                      </View>
                    </Animated.View>
                  </Pressable>
                </Link>
              );
            })}
          </Animated.ScrollView>
        )}
      </View>

      <PizzaMenu />
    </View>
  );
}

const s = StyleSheet.create({
  screen: { flex: 1, backgroundColor: COLORS.bgPrimary },
  loadingContainer: { flex: 1, justifyContent: "center", alignItems: "center", backgroundColor: COLORS.bgPrimary },
  loadingText: { marginTop: SPACING.md, ...TYPO.bodySm, color: COLORS.textTertiary },

  sectionHeader: { paddingHorizontal: SPACING.xxl, marginBottom: SPACING.lg },
  sectionTitle: { ...TYPO.h1, color: COLORS.textPrimary },
  sectionSub: { ...TYPO.caption, color: COLORS.textTertiary, marginTop: 2 },

  emptyContainer: { alignItems: "center", marginTop: 50, paddingHorizontal: 40 },
  emptyImage: { width: 100, height: 100, marginBottom: 10, opacity: 0.3 },
  emptyTitle: { ...TYPO.body, color: COLORS.textTertiary },
  emptyDate: { ...TYPO.caption, color: COLORS.textPlaceholder },

  card: {
    backgroundColor: COLORS.bgCardElevated, borderRadius: RADIUS.xxl,
    marginRight: 14, overflow: "hidden",
    borderWidth: 1, borderColor: COLORS.glassBorder, ...SHADOWS.lg,
  },
  cardImageWrapper: { height: "45%", backgroundColor: COLORS.bgSecondary, position: "relative" },
  cardImage: { width: "100%", height: "100%" },
  cardBadge: {
    position: "absolute", top: 12, right: 12,
    backgroundColor: "rgba(255,255,255,0.85)", paddingHorizontal: 10, paddingVertical: 4,
    borderRadius: RADIUS.pill, borderWidth: 1, borderColor: COLORS.glassBorder,
  },
  cardBadgeText: { ...TYPO.caption, color: COLORS.textPrimary, fontWeight: "600" },
  cardContent: { padding: SPACING.xl, flex: 1, justifyContent: "space-between" },
  cardTitle: { ...TYPO.h3, color: COLORS.textPrimary, lineHeight: 26 },
  cardSummary: { ...TYPO.bodySm, color: COLORS.textTertiary, lineHeight: 20, marginTop: SPACING.sm },
  cardFooter: { flexDirection: "row", justifyContent: "flex-end", marginTop: SPACING.sm },
  cardReadBtn: { ...TYPO.label, color: COLORS.primaryLight },
});
