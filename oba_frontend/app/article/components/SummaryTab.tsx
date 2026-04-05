// oba_fronted/app/article/components/SummaryTab.tsx

import { View, Text, StyleSheet } from "react-native";

export default function SummaryTab({ summary, summaryBullets }: { summary?: string | null; summaryBullets?: string[] | null }) {
  // summaryBullets 배열 또는 summary 문자열 사용
  const bullets = summaryBullets && summaryBullets.length > 0 ? summaryBullets : null;
  const text = typeof summary === "string" && summary.length > 0 ? summary : null;

  if (!bullets && !text) {
    return (
      <View style={styles.container}>
        <Text style={{ fontSize: 16, color: "#999", textAlign: "center", marginTop: 40 }}>요약을 준비 중이에요.</Text>
      </View>
    );
  }
  return (
    <View style={styles.container}>
      <Text style={styles.title}>🤖 AI 요약</Text>
      {bullets
        ? bullets.map((b, i) => <Text key={i} style={styles.content}>{b}</Text>)
        : <Text style={styles.content}>{text}</Text>
      }
    </View>
  );
}

const styles = StyleSheet.create({
  container: { padding: 20 },

  title: {
    fontSize: 20,
    fontWeight: "700",
    marginBottom: 14,
    color: "#222",
  },

  content: {
    fontSize: 15,
    lineHeight: 22,
    color: "#333",
  },
});
