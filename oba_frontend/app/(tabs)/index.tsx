// oba_frontend/app/(tabs)/index.tsx

import { useRef, useState, useEffect } from "react";
import {
  View,
  Text,
  Image,
  Animated,
  useWindowDimensions,
  Pressable,
  ActivityIndicator,
} from "react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { Link } from "expo-router";
import { apiClient } from "../../src/api/apiClient";
import PizzaMenu from "../components/PizzaMenu";
import HomeHeader from "../components/HomeHeader";

interface ArticleSummary {
  articleId: string;
  title: string;
  summaryBullets?: string[];
  thumbnailUrl?: string;
  servingDate?: string;
}

interface UserProfile {
  nickname: string;
  profileImage: string;
}

// Extract first image URL from article detail content
function extractImageFromContent(content: string[]): string | null {
  if (!content) return null;
  for (const line of content) {
    if (line.startsWith("<img>")) {
      return line.replace("<img>", "");
    }
  }
  return null;
}

export default function Home() {
  const insets = useSafeAreaInsets();
  const { width, height } = useWindowDimensions();

  const scrollX = useRef(new Animated.Value(0)).current;

  const CARD_WIDTH = width * 0.75;
  const CARD_HEIGHT = Math.min(height * 0.55, 550);
  const SIDE_SPACING = (width - CARD_WIDTH) / 2;
  const SNAP_INTERVAL = CARD_WIDTH + 12;

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

        // Fetch articles
        try {
          const articlesRes = await apiClient.get("/api/articles/latest?limit=10");
          const data = articlesRes.data;
          let articleList: ArticleSummary[] = Array.isArray(data) ? data : [];

          // Filter today's articles and limit to 5
          const today = new Date().toISOString().split("T")[0];
          const todayArticles = articleList.filter(
            (a) => a.servingDate === today
          );
          articleList = todayArticles.length > 0 ? todayArticles.slice(0, 5) : articleList.slice(0, 5);

          // Fetch thumbnails from article details
          const articlesWithImages = await Promise.all(
            articleList.map(async (article) => {
              try {
                const detailRes = await apiClient.get(`/api/articles/${article.articleId}`);
                const imageUrl = extractImageFromContent(detailRes.data.content);
                return { ...article, thumbnailUrl: imageUrl || undefined };
              } catch {
                return article;
              }
            })
          );

          setArticles(articlesWithImages);
        } catch (e) {
          console.error("Articles fetch failed:", e);
          setArticles([]);
        }

        // Fetch user profile
        try {
          const profileRes = await apiClient.get("/api/users/me");
          setUserProfile({
            nickname: profileRes.data.displayName || profileRes.data.name || "한입기사님",
            profileImage: profileRes.data.picture || "",
          });
          setStreak(profileRes.data.consecutiveDays || 0);
          const weeklyLog = profileRes.data.weeklyLog || [];
          setDaySliceCounts(weeklyLog.map((v: boolean) => (v ? 1 : 0)));
        } catch (e) {
          console.error("Profile fetch failed:", e);
          setUserProfile({ nickname: "한입기사님", profileImage: "" });
        }
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  if (loading) {
    return (
      <View style={{ flex: 1, justifyContent: "center", alignItems: "center", backgroundColor: "#F5FAFF" }}>
        <ActivityIndicator size="large" color="#007AFF" />
        <Text style={{ marginTop: 10, color: "#666" }}>따끈한 피자 기사를 굽는 중... 🍕</Text>
      </View>
    );
  }

  return (
    <View style={{ flex: 1, paddingTop: insets.top + 10, backgroundColor: "#F5FAFF" }}>
      {userProfile && (
        <HomeHeader
          user={userProfile}
          streak={streak}
          date={getFormattedDate()}
          daySliceCounts={daySliceCounts}
        />
      )}

      <View style={{ marginTop: 0 }}>
        <Text style={{ fontSize: 20, fontWeight: "800", marginLeft: 24, marginBottom: 16, color: "#191F28" }}>
          오늘의 기사
        </Text>

        {articles.length === 0 ? (
          <View style={{ alignItems: "center", marginTop: 50, paddingHorizontal: 40 }}>
            <Image
              source={require("../../assets/knight/hand.png")}
              style={{ width: 100, height: 100, marginBottom: 10, opacity: 0.5 }}
              resizeMode="contain"
            />
            <Text style={{ color: "#999", fontSize: 16, marginBottom: 5 }}>아직 도착한 기사가 없어요.</Text>
            <Text style={{ color: "#ccc", fontSize: 12 }}>({new Date().toLocaleDateString()} 기준)</Text>
          </View>
        ) : (
          <Animated.ScrollView
            horizontal
            showsHorizontalScrollIndicator={false}
            snapToOffsets={articles.map((_, i) => i * SNAP_INTERVAL)}
            snapToAlignment="start"
            decelerationRate="fast"
            disableIntervalMomentum={true}
            scrollEventThrottle={16}
            pagingEnabled={false}
            contentContainerStyle={{ paddingHorizontal: SIDE_SPACING }}
            onScroll={Animated.event(
              [{ nativeEvent: { contentOffset: { x: scrollX } } }],
              { useNativeDriver: true }
            )}
          >
            {articles.map((item, i) => {
              const inputRange = [
                (i - 1) * SNAP_INTERVAL,
                i * SNAP_INTERVAL,
                (i + 1) * SNAP_INTERVAL,
              ];

              const scale = scrollX.interpolate({
                inputRange,
                outputRange: [0.93, 1, 0.93],
                extrapolate: "clamp",
              });

              const summaryText = item.summaryBullets && item.summaryBullets.length > 0
                ? item.summaryBullets.map(s => `• ${s}`).join("\n")
                : "요약 내용이 없습니다.";

              return (
                <Link key={i} href={`/article/${item.articleId}`} asChild>
                  <Pressable>
                    <Animated.View
                      style={{
                        width: CARD_WIDTH,
                        height: CARD_HEIGHT,
                        backgroundColor: "#fff",
                        borderRadius: 24,
                        padding: 0,
                        marginRight: 12,
                        transform: [{ scale }],
                        shadowColor: "#000",
                        shadowOpacity: 0.1,
                        shadowRadius: 12,
                        elevation: 5,
                        overflow: "hidden",
                      }}
                    >
                      <View style={{ height: "45%", backgroundColor: "#F2F4F6" }}>
                        <Image
                          source={item.thumbnailUrl ? { uri: item.thumbnailUrl } : require("../../assets/knight/deliever.png")}
                          style={{ width: "100%", height: "100%" }}
                          resizeMode="cover"
                        />
                      </View>

                      <View style={{ padding: 20, flex: 1 }}>
                        <Text style={{ fontSize: 18, fontWeight: "800", color: "#191F28", marginBottom: 12 }} numberOfLines={2}>
                          {item.title}
                        </Text>

                        <Text style={{ fontSize: 14, lineHeight: 22, color: "#4E5968", flex: 1 }} numberOfLines={4}>
                          {summaryText}
                        </Text>
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
