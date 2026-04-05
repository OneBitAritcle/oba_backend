import React, { useState, useEffect } from "react";
import { View, Text, StyleSheet, ActivityIndicator, LayoutChangeEvent } from "react-native";
import Svg, { Path, Circle, Line } from "react-native-svg";
import { apiClient } from "../../../src/api/apiClient";

/**
 * 📍 API 명세: /BACKEND_API_SPEC.md - "3️⃣ 요일별 정답률 조회"
 * 엔드포인트: GET /api/report/daily-stats
 * 응답 배열의 각 항목 구조
 */
export interface DailyData {
  date?: string;        // 해당 날짜 (YYYY-MM-DD)
  day: string;          // 요일 (Mon/Tue/Wed/Thu/Fri/Sat/Sun)
  accuracy: number;     // 정답률 (0~100)
  attemptedQuizzes?: number;  // 풀이한 문제 수
  correctQuizzes?: number;    // 맞춘 문제 수
}

export default function DailyChart() {
  const [chartData, setChartData] = useState<DailyData[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [chartWidth, setChartWidth] = useState<number>(0);

  // 차트 설정값
  const CHART_HEIGHT = 180; 
  const PADDING_HORIZONTAL = 20; 
  const GRAPH_COLOR = "#7FCD7F";
  
  const TOP_PADDING = 15; 

  useEffect(() => {
    // 📌 데이터 페칭 로직
    // 
    // ✅ 중요: user_id는 JWT 토큰에서 자동으로 추출됨 (Query Parameter 불필요)
    // 
    // 🚀 백엔드 연동 시: import { apiClient } from "../../../../src/api/apiClient";
    //    const response = await apiClient.get("/api/report/daily-stats");
    //    setChartData(response.data);
    
    const fetchDailyStats = async () => {
      try {
        setLoading(true);
        const response = await apiClient.get("/api/report/daily-stats?days=7");
        setChartData(response.data);
      } catch (err) {
        console.error("DailyChart 데이터 로드 실패:", err);
        setChartData([]);
      } finally {
        setLoading(false);
      }
    };
    fetchDailyStats();
  }, []);

  // ✅ [수정 2] 좌표 계산식 변경 (TOP_PADDING 반영)
  const getCoordinates = (index: number, value: number) => {
    if (chartData.length === 0 || chartWidth === 0) return { x: 0, y: 0 };
    
    // X축 (동일)
    const availableWidth = chartWidth - (PADDING_HORIZONTAL * 2);
    const x = (index / (chartData.length - 1)) * availableWidth + PADDING_HORIZONTAL;
    
    // Y축: (전체 높이 - 여백)을 기준으로 비율 계산 후, 여백만큼 내림
    // value = 100 일 때 -> y = TOP_PADDING (15)
    // value = 0   일 때 -> y = CHART_HEIGHT (180)
    const drawingHeight = CHART_HEIGHT - TOP_PADDING;
    const y = TOP_PADDING + (1 - value / 100) * drawingHeight;
    
    return { x, y };
  };

  const createPath = () => {
    if (chartData.length === 0) return "";
    return chartData.map((item, index) => {
      const { x, y } = getCoordinates(index, item.accuracy);
      return `${index === 0 ? "M" : "L"} ${x} ${y}`;
    }).join(" ");
  };

  const onLayout = (event: LayoutChangeEvent) => {
    const { width } = event.nativeEvent.layout;
    setChartWidth(width);
  };

  if (loading) {
    return (
      <View style={[styles.cardContainer, styles.centerContent]}>
        <ActivityIndicator size="large" color={GRAPH_COLOR} />
      </View>
    );
  }

  return (
    <View style={styles.cardContainer}>
      <View style={styles.headerContainer}>
        <View>
          <Text style={styles.title}>주간 정답률</Text>
          <Text style={styles.subtitle}>지난 7일간의 정답률 변화</Text>
        </View>
        <View style={styles.legendItem}>
          <View style={[styles.dot, { backgroundColor: GRAPH_COLOR }]} />
          <Text style={styles.legendText}>정답률(%)</Text>
        </View>
      </View>

      <View style={styles.chartBody}>
        {/* Y-Axis Labels */}
        <View style={styles.yAxisColumn}>
          {["100", "75", "50", "25", "0"].map((label) => (
            <Text key={label} style={styles.axisText}>{label}</Text>
          ))}
        </View>

        {/* Graph Area */}
        <View style={styles.graphContainer} onLayout={onLayout}>
          {chartWidth > 0 && (
            <>
              <Svg height={CHART_HEIGHT + 10} width={chartWidth}>
                
                {/* ✅ [수정 3] 배경 그리드 라인도 동일한 공식 적용 */}
                {[0, 25, 50, 75, 100].map((val) => {
                   const drawingHeight = CHART_HEIGHT - TOP_PADDING;
                   const y = TOP_PADDING + (1 - val / 100) * drawingHeight;
                   
                   return (
                     <Line
                       key={val}
                       x1="0"
                       y1={y}
                       x2={chartWidth}
                       y2={y}
                       stroke="#F0F0F0"
                       strokeWidth="1"
                     />
                   );
                })}

                <Path
                  d={createPath()}
                  fill="none"
                  stroke={GRAPH_COLOR}
                  strokeWidth="3"
                />

                {chartData.map((item, index) => {
                  const { x, y } = getCoordinates(index, item.accuracy);
                  return (
                    <Circle 
                      key={index} 
                      cx={x} 
                      cy={y} 
                      r="4" 
                      fill="#fff" 
                      stroke={GRAPH_COLOR} 
                      strokeWidth="2" 
                    />
                  );
                })}
              </Svg>

              <View style={styles.xAxisContainer}>
                {chartData.map((item, index) => {
                   const availableWidth = chartWidth - (PADDING_HORIZONTAL * 2);
                   const x = (index / (chartData.length - 1)) * availableWidth + PADDING_HORIZONTAL;
                   return (
                     <Text 
                       key={item.day} 
                       style={[styles.dayText, { left: x - 15 }]} 
                     >
                       {item.day}
                     </Text>
                   );
                })}
              </View>
            </>
          )}
        </View>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  // 기존 스타일 유지
  cardContainer: {
    backgroundColor: "#fff",
    borderRadius: 20,
    padding: 24,
    marginHorizontal: 20,
    marginVertical: 12,
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.08,
    shadowRadius: 12,
    elevation: 4,
    minHeight: 300,
  },
  centerContent: {
    justifyContent: "center",
    alignItems: "center",
  },
  headerContainer: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "flex-start",
    marginBottom: 30,
  },
  title: {
    fontSize: 18,
    fontWeight: "bold",
    color: "#222",
    marginBottom: 6,
  },
  subtitle: {
    fontSize: 13,
    color: "#888",
  },
  legendItem: {
    flexDirection: "row",
    alignItems: "center",
  },
  dot: {
    width: 8,
    height: 8,
    borderRadius: 4,
    marginRight: 6,
  },
  legendText: {
    fontSize: 12,
    color: "#666",
  },
  chartBody: {
    flexDirection: "row",
    height: 230,
  },
  yAxisColumn: {
    width: 30,
    justifyContent: "space-between",
    paddingBottom: 30,
    alignItems: "flex-end",
    paddingRight: 10,
    height: 180 + 14, // Chart Height + Font Height 보정
    // 여기서 높이 보정을 TOP_PADDING 만큼 살짝 안 맞을 수 있으나 
    // Y축 텍스트는 flex space-between이라 얼추 맞음. 
    // 정확히 맞추려면 marginTop: TOP_PADDING 추가 가능.
    paddingTop: 15, // ✅ Y축 텍스트도 패딩만큼 내려줌
  },
  axisText: {
    fontSize: 11,
    color: "#aaa",
    height: 14, 
    lineHeight: 14,
  },
  graphContainer: {
    flex: 1,
    height: 230,
    position: "relative",
  },
  xAxisContainer: {
    position: "absolute",
    top: 190, 
    width: "100%",
    height: 30,
  },
  dayText: {
    position: "absolute",
    width: 30,
    textAlign: "center",
    fontSize: 11,
    color: "#666",
  },
});