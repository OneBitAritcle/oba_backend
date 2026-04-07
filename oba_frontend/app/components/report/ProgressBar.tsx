import { View, Text, StyleSheet } from "react-native";

/**
 * 진도바 컴포넌트 (학습 진도 표시)
 * - "재학습 현황" 타이틀
 * - 진행률 바 (시각적)
 * - 진행된 문제 수 / 전체 문제 수
 * - 진도율 백분위 표시
 *
 * 📍 API 명세: /BACKEND_API_SPEC.md - "2️⃣ 전체 학습 진도 조회"
 * 엔드포인트: GET /api/report/progress
 * 응답: { solvedCount, totalCount, progressPercentage }
 *
 * 데이터 흐름: report/index.tsx → fetchReportData()
 *            → apiClient.get("/api/report/progress")
 *            → setReportData() → ProgressBar에 props 전달
 */

interface ProgressBarProps {
  solvedCount?: number;
  totalCount?: number;
}

export default function ProgressBar({
  solvedCount = 150,
  totalCount = 200,
}: ProgressBarProps) {
  const progress = (solvedCount / totalCount) * 100;

  return (
    <View style={styles.container}>
      {/* 타이틀 */}
      <Text style={styles.title}>재학습 현황</Text>

      {/* 진행률 바 */}
      <View style={styles.barContainer}>
        <View
          style={[
            styles.barFill,
            {
              width: `${progress}%`,
            },
          ]}
        />
      </View>

      {/* 진행 상황 텍스트 */}
      <View style={styles.infoContainer}>
        <Text style={styles.infoText}>
          전제 {totalCount}문제 중 {solvedCount}문제 풀이 완료
        </Text>
        <Text style={styles.percentage}>{progress.toFixed(0)}%</Text>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    marginTop: 24,
    paddingHorizontal: 16,
  },
  title: {
    fontSize: 14,
    fontWeight: "600",
    color: "#222",
    marginBottom: 12,
  },
  barContainer: {
    height: 12,
    backgroundColor: "#E8EEF5",
    borderRadius: 6,
    overflow: "hidden",
    marginBottom: 12,
  },
  barFill: {
    height: "100%",
    backgroundColor: "#5B9FFF",
    borderRadius: 6,
  },
  infoContainer: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
  },
  infoText: {
    fontSize: 12,
    color: "#666",
  },
  percentage: {
    fontSize: 14,
    fontWeight: "700",
    color: "#222",
  },
});
