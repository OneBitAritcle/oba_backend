import React, { useState, useEffect } from "react";
import { View, Text, StyleSheet, ActivityIndicator, LayoutChangeEvent } from "react-native";
import Svg, { Path, Circle, Line } from "react-native-svg";
import { apiClient } from "../../../src/api/apiClient";
import { COLORS, RADIUS, SHADOWS, TYPO, SPACING } from "../../../constants/theme";

export interface DailyData { date?: string; day: string; accuracy: number; attemptedQuizzes?: number; correctQuizzes?: number; }

export default function DailyChart() {
  const [chartData, setChartData] = useState<DailyData[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [chartWidth, setChartWidth] = useState<number>(0);
  const CHART_HEIGHT = 180; const PADDING_HORIZONTAL = 20;
  const GRAPH_COLOR = COLORS.primaryLight;
  const TOP_PADDING = 15;

  useEffect(() => {
    const fetchDailyStats = async () => { try { setLoading(true); const r = await apiClient.get("/api/report/daily-stats?days=7"); setChartData(r.data); } catch { setChartData([]); } finally { setLoading(false); } };
    fetchDailyStats();
  }, []);

  const getCoordinates = (index: number, value: number) => {
    if (chartData.length === 0 || chartWidth === 0) return { x: 0, y: 0 };
    const availableWidth = chartWidth - (PADDING_HORIZONTAL * 2);
    const x = (index / (chartData.length - 1)) * availableWidth + PADDING_HORIZONTAL;
    const drawingHeight = CHART_HEIGHT - TOP_PADDING;
    const y = TOP_PADDING + (1 - value / 100) * drawingHeight;
    return { x, y };
  };
  const createPath = () => { if (chartData.length === 0) return ""; return chartData.map((item, i) => { const { x, y } = getCoordinates(i, item.accuracy); return `${i === 0 ? "M" : "L"} ${x} ${y}`; }).join(" "); };
  const onLayout = (e: LayoutChangeEvent) => { setChartWidth(e.nativeEvent.layout.width); };

  if (loading) return <View style={[s.card, s.centerContent]}><ActivityIndicator size="large" color={COLORS.primary} /></View>;

  return (
    <View style={s.card}>
      <View style={s.header}>
        <View><Text style={s.title}>주간 정답률</Text><Text style={s.subtitle}>지난 7일간의 정답률 변화</Text></View>
        <View style={s.legendItem}><View style={[s.legendDot, { backgroundColor: GRAPH_COLOR }]} /><Text style={s.legendText}>정답률(%)</Text></View>
      </View>
      <View style={s.chartBody}>
        <View style={s.yAxisColumn}>{["100", "75", "50", "25", "0"].map((l) => <Text key={l} style={s.axisText}>{l}</Text>)}</View>
        <View style={s.graphContainer} onLayout={onLayout}>
          {chartWidth > 0 && (<>
            <Svg height={CHART_HEIGHT + 10} width={chartWidth}>
              {[0, 25, 50, 75, 100].map((v) => { const dh = CHART_HEIGHT - TOP_PADDING; const y = TOP_PADDING + (1 - v / 100) * dh; return <Line key={v} x1="0" y1={y} x2={chartWidth} y2={y} stroke={COLORS.glassBorder} strokeWidth="1" />; })}
              <Path d={createPath()} fill="none" stroke={GRAPH_COLOR} strokeWidth="3" />
              {chartData.map((item, i) => { const { x, y } = getCoordinates(i, item.accuracy); return <Circle key={i} cx={x} cy={y} r="4" fill={COLORS.bgPrimary} stroke={GRAPH_COLOR} strokeWidth="2" />; })}
            </Svg>
            <View style={s.xAxisContainer}>{chartData.map((item, i) => { const aw = chartWidth - (PADDING_HORIZONTAL * 2); const x = (i / (chartData.length - 1)) * aw + PADDING_HORIZONTAL; return <Text key={item.day} style={[s.dayText, { left: x - 15 }]}>{item.day}</Text>; })}</View>
          </>)}
        </View>
      </View>
    </View>
  );
}

const s = StyleSheet.create({
  card: { backgroundColor: COLORS.bgCardElevated, borderRadius: RADIUS.card, padding: SPACING.xxl, marginHorizontal: SPACING.xl, marginVertical: SPACING.md, borderWidth: 1, borderColor: COLORS.glassBorder, ...SHADOWS.md, minHeight: 300 },
  centerContent: { justifyContent: "center", alignItems: "center" },
  header: { flexDirection: "row", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 30 },
  title: { ...TYPO.h3, color: COLORS.textPrimary, marginBottom: 6 },
  subtitle: { ...TYPO.caption, color: COLORS.textTertiary },
  legendItem: { flexDirection: "row", alignItems: "center" },
  legendDot: { width: 8, height: 8, borderRadius: 4, marginRight: 6 },
  legendText: { ...TYPO.caption, color: COLORS.textTertiary },
  chartBody: { flexDirection: "row", height: 230 },
  yAxisColumn: { width: 30, justifyContent: "space-between", paddingBottom: 30, alignItems: "flex-end", paddingRight: 10, height: 194, paddingTop: 15 },
  axisText: { fontSize: 11, color: COLORS.textPlaceholder, height: 14, lineHeight: 14 },
  graphContainer: { flex: 1, height: 230, position: "relative" },
  xAxisContainer: { position: "absolute", top: 190, width: "100%", height: 30 },
  dayText: { position: "absolute", width: 30, textAlign: "center", fontSize: 11, color: COLORS.textTertiary },
});
