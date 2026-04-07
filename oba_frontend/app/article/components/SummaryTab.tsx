import { View, Text, StyleSheet, ScrollView } from "react-native";
import { COLORS, RADIUS, SHADOWS, TYPO, SPACING } from "../../../constants/theme";

export default function SummaryTab({ summary, summaryBullets }: { summary?: string | null; summaryBullets?: string[] | null }) {
  const bullets = summaryBullets && summaryBullets.length > 0 ? summaryBullets : null;
  const text = typeof summary === "string" && summary.length > 0 ? summary : null;

  if (!bullets && !text) {
    return <View style={styles.container}><Text style={{ ...TYPO.body, color: COLORS.textTertiary, textAlign: "center", marginTop: 40 }}>요약을 준비 중이에요.</Text></View>;
  }
  return (
    <ScrollView contentContainerStyle={styles.container} showsVerticalScrollIndicator={false}>
      <View style={styles.badge}><Text style={styles.badgeText}>AI</Text></View>
      <Text style={styles.title}>요약</Text>
      <View style={styles.card}>
        {bullets ? bullets.map((b, i) => <Text key={i} style={styles.content}>{b}</Text>) : <Text style={styles.content}>{text}</Text>}
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { padding: SPACING.xl, paddingBottom: 40 },
  badge: { backgroundColor: COLORS.primarySurface, paddingHorizontal: 10, paddingVertical: 4, borderRadius: RADIUS.sm, alignSelf: "flex-start", marginBottom: SPACING.sm, borderWidth: 1, borderColor: COLORS.primary + "30" },
  badgeText: { ...TYPO.caption, fontWeight: "700", color: COLORS.primaryLight },
  title: { ...TYPO.h2, color: COLORS.textPrimary, marginBottom: SPACING.lg },
  card: { backgroundColor: COLORS.bgCardElevated, borderRadius: RADIUS.card, padding: SPACING.xl, borderWidth: 1, borderColor: COLORS.glassBorder, ...SHADOWS.sm },
  content: { ...TYPO.body, color: COLORS.textSecondary, fontSize: 15 },
});
