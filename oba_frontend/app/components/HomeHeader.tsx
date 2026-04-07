import React from "react";
import { View, Text, Image, StyleSheet, TouchableOpacity } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useRouter } from "expo-router";
import { COLORS, RADIUS, SHADOWS, TYPO, SPACING } from "../../constants/theme";

interface HomeHeaderProps {
  user: { nickname: string; profileImage: string };
  streak: number;
  date: string;
  daySliceCounts?: number[];
}

export default function HomeHeader({ user, streak, date, daySliceCounts }: HomeHeaderProps) {
  const router = useRouter();
  const days = ["월", "화", "수", "목", "금", "토", "일"];
  const todayIndex = new Date().getDay() === 0 ? 6 : new Date().getDay() - 1;

  return (
    <View style={styles.container}>
      <View style={styles.card}>
        <View style={styles.topRow}>
          <View style={styles.profileInfo}>
            <View style={styles.avatarContainer}>
              <Image
                source={
                  user.profileImage && (user.profileImage.startsWith("http") || user.profileImage.startsWith("https"))
                    ? { uri: user.profileImage }
                    : require("../../assets/knight/basic_profile.png")
                }
                style={styles.avatar}
              />
            </View>
            <View style={styles.textContainer}>
              <TouchableOpacity style={styles.nicknameRow} onPress={() => router.push("/my")} activeOpacity={0.6}>
                <Text style={styles.nickname}>{user.nickname}</Text>
                <Ionicons name="chevron-forward" size={18} color={COLORS.textTertiary} />
              </TouchableOpacity>
              <Text style={styles.dateText}>{date}</Text>
              <View style={styles.streakBadge}>
                <Text style={styles.streakText}>🔥 연속 학습 {streak}일</Text>
              </View>
            </View>
          </View>
        </View>

        <View style={styles.daysRow}>
          {days.map((day, index) => {
            const sliceCount = daySliceCounts?.[index] ?? 0;
            const isToday = index === todayIndex;
            const done = sliceCount > 0;
            return (
              <View key={index} style={styles.dayItem}>
                <View style={[styles.dayCircle, isToday && styles.todayCircle, done && styles.doneCircle]}>
                  {done ? (
                    <Image source={require("../../assets/navi/navi_1.png")} style={styles.pizzaIcon} resizeMode="contain" />
                  ) : (
                    <Text style={styles.dayEmoji}>{isToday ? "📍" : ""}</Text>
                  )}
                </View>
                <Text style={[styles.dayText, isToday && styles.todayDayText]}>{day}</Text>
              </View>
            );
          })}
        </View>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { paddingHorizontal: SPACING.xxl, marginBottom: SPACING.xxl },
  card: {
    backgroundColor: COLORS.bgCard,
    borderRadius: RADIUS.xxl,
    padding: SPACING.xxl,
    borderWidth: 1,
    borderColor: COLORS.border,
    ...SHADOWS.md,
  },
  topRow: { flexDirection: "row", justifyContent: "space-between", alignItems: "center", marginBottom: SPACING.xl },
  profileInfo: { flexDirection: "row", alignItems: "center" },
  avatarContainer: {
    width: 64, height: 64, borderRadius: 32,
    backgroundColor: COLORS.bgSecondary, padding: 2, marginRight: SPACING.lg,
    overflow: "hidden", borderWidth: 2, borderColor: COLORS.primary + "40",
  },
  avatar: { width: "100%", height: "100%", borderRadius: 30, resizeMode: "cover" },
  textContainer: { justifyContent: "center" },
  nicknameRow: { flexDirection: "row", alignItems: "center" },
  nickname: { ...TYPO.h2, color: COLORS.textPrimary, marginRight: 4 },
  dateText: { ...TYPO.caption, color: COLORS.textTertiary, marginVertical: 2 },
  streakBadge: {
    backgroundColor: COLORS.primarySurface,
    paddingHorizontal: 10, paddingVertical: 4,
    borderRadius: RADIUS.pill, marginTop: 4, alignSelf: "flex-start",
    borderWidth: 1, borderColor: COLORS.primary + "20",
  },
  streakText: { ...TYPO.caption, fontWeight: "700", color: COLORS.primaryDark },
  daysRow: { flexDirection: "row", justifyContent: "space-between", marginTop: SPACING.sm },
  dayItem: { alignItems: "center" },
  dayCircle: {
    width: 36, height: 36, borderRadius: 18,
    backgroundColor: COLORS.bgSecondary, justifyContent: "center", alignItems: "center",
  },
  todayCircle: { backgroundColor: COLORS.primarySurface, borderWidth: 1.5, borderColor: COLORS.primary + "40" },
  doneCircle: { backgroundColor: "transparent", borderWidth: 0 },
  pizzaIcon: { width: 30, height: 30 },
  dayEmoji: { fontSize: 14 },
  dayText: { ...TYPO.caption, color: COLORS.textTertiary, marginTop: 4 },
  todayDayText: { color: COLORS.primary, fontWeight: "700" },
});
