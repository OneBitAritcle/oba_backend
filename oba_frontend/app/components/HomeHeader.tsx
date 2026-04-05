import React from "react";
import { View, Text, Image, StyleSheet, TouchableOpacity, Platform } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useRouter } from "expo-router";
import Svg, { Defs, G, Path, RadialGradient, Stop, Circle } from "react-native-svg";

const SHOW_CALENDAR_BUTTON = false;

interface HomeHeaderProps {
  user: {
    nickname: string;
    profileImage: string;
  };
  streak: number;
  date: string;
  daySliceCounts?: number[]; // Mon..Sun, each 0..5
}

function MiniPizza({ count, size = 35 }: { count: number; size?: number }) {
  const safe = Math.max(0, Math.min(5, count));
  const crustPath = "M 100 10 A 90 90 0 0 1 185.595 72.188 L 173.273 77.676 A 76 76 0 0 0 100 24 Z";
  const cheesePath = "M 100 100 L 100 24 A 76 76 0 0 1 173.273 77.676 Z";

  return (
    <Svg width={size} height={size} viewBox="10 10 180 180">
      <Defs>
        <RadialGradient id="miniCheese" cx="50%" cy="45%" r="70%">
          <Stop offset="0%" stopColor="#FFE9A6" />
          <Stop offset="100%" stopColor="#FFC94D" />
        </RadialGradient>
        <RadialGradient id="miniPep" cx="40%" cy="40%" r="70%">
          <Stop offset="0%" stopColor="#FF7A59" />
          <Stop offset="100%" stopColor="#C62828" />
        </RadialGradient>
      </Defs>
      {Array.from({ length: safe }).map((_, i) => (
        <G key={i} originX={100} originY={100} rotation={72 * i}>
          <Path d={crustPath} fill="#E8A04B" stroke="#C97A22" strokeWidth={4} />
          <Path d={cheesePath} fill="url(#miniCheese)" stroke="#E0A800" strokeWidth={4} />
          <Circle cx={126.5} cy={63.6} r={10} fill="url(#miniPep)" stroke="#8E1B1B" strokeWidth={3} />
          <Circle cx={122} cy={58} r={2.8} fill="#FFF4CC" opacity={0.6} />
        </G>
      ))}
    </Svg>
  );
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
                <Ionicons name="chevron-forward" size={18} color="#999" />
              </TouchableOpacity>
              <Text style={styles.dateText}>{date}</Text>
              <View style={styles.streakRow}>
                <Text style={styles.streakIcon}>🔥</Text>
                <Text style={styles.streakText}>연속 학습 {streak}일</Text>
              </View>
            </View>
          </View>

          {SHOW_CALENDAR_BUTTON && (
            <TouchableOpacity style={styles.calendarBtn} onPress={() => router.push("/history")} activeOpacity={0.7}>
              <Ionicons name="calendar-outline" size={18} color="#4E5968" />
            </TouchableOpacity>
          )}
        </View>

        <View style={styles.daysRow}>
          {days.map((day, index) => {
            const sliceCount = daySliceCounts?.[index] ?? 0;
            const isToday = index === todayIndex;
            return (
              <View key={index} style={[styles.dayCircle, isToday && styles.todayCircle]}>
                {sliceCount > 0 && (
                  <View style={styles.pizzaBadge}>
                    <MiniPizza count={sliceCount} size={35} />
                  </View>
                )}
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
  container: {
    paddingHorizontal: 24,
    marginBottom: 24,
  },
  card: {
    backgroundColor: "#FFF9E6",
    borderRadius: 32,
    padding: 24,
    ...Platform.select({
      ios: {
        shadowColor: "#000",
        shadowOffset: { width: 0, height: 4 },
        shadowOpacity: 0.05,
        shadowRadius: 10,
      },
      android: { elevation: 3 },
    }),
  },
  topRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: 20,
  },
  calendarBtn: {
    width: 34,
    height: 34,
    borderRadius: 17,
    backgroundColor: "#fff",
    borderWidth: 1,
    borderColor: "#E5E8EB",
    alignItems: "center",
    justifyContent: "center",
  },
  profileInfo: {
    flexDirection: "row",
    alignItems: "center",
  },
  avatarContainer: {
    width: 64,
    height: 64,
    borderRadius: 32,
    backgroundColor: "#fff",
    padding: 2,
    marginRight: 16,
    overflow: "hidden",
    borderWidth: 1,
    borderColor: "#F2F4F6",
  },
  avatar: {
    width: "100%",
    height: "100%",
    borderRadius: 30,
    resizeMode: "cover",
  },
  textContainer: {
    justifyContent: "center",
  },
  nicknameRow: {
    flexDirection: "row",
    alignItems: "center",
  },
  nickname: {
    fontSize: 20,
    fontWeight: "800",
    color: "#191F28",
    marginRight: 4,
  },
  dateText: {
    fontSize: 14,
    color: "#8B95A1",
    marginVertical: 2,
  },
  streakRow: {
    flexDirection: "row",
    alignItems: "center",
    marginTop: 4,
  },
  streakIcon: {
    fontSize: 16,
    marginRight: 4,
  },
  streakText: {
    fontSize: 15,
    fontWeight: "600",
    color: "#4E5968",
  },
  daysRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    marginTop: 8,
  },
  dayCircle: {
    width: 36,
    height: 36,
    borderRadius: 18,
    backgroundColor: "#F2F4F6",
    justifyContent: "center",
    alignItems: "center",
    position: "relative",
  },
  todayCircle: {
    backgroundColor: "#fff",
    borderWidth: 1.5,
    borderColor: "#E5E8EB",
  },
  dayText: {
    fontSize: 13,
    color: "#8B95A1",
    fontWeight: "500",
    zIndex: 1,
  },
  todayDayText: {
    color: "#191F28",
    fontWeight: "700",
  },
  pizzaBadge: {
    position: "absolute",
    ...StyleSheet.absoluteFillObject,
    justifyContent: "center",
    alignItems: "center",
    zIndex: 3,
  },
});
