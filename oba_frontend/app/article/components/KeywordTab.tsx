import { View, Text, StyleSheet, ScrollView, Image } from "react-native";
import { COLORS, RADIUS, SHADOWS, TYPO, SPACING } from "../../../constants/theme";

const pizzaImages = [
  require("../../../assets/pizza/comb.png"), require("../../../assets/pizza/hwaa.png"),
  require("../../../assets/pizza/mar.png"), require("../../../assets/pizza/pep.png"),
];

export default function KeywordTab({ keywords = [] }) {
  if (!keywords || !Array.isArray(keywords) || keywords.length === 0) {
    return <ScrollView contentContainerStyle={{ padding: SPACING.xl, alignItems: "center", paddingTop: 60 }}><Text style={{ ...TYPO.body, color: COLORS.textTertiary }}>키워드를 준비 중이에요.</Text></ScrollView>;
  }
  return (
    <ScrollView contentContainerStyle={styles.container} showsVerticalScrollIndicator={false}>
      {keywords.map((item: any, index: number) => {
        const word = typeof item === "string" ? item : item.keyword || "";
        const desc = typeof item === "object" && item.description ? item.description : null;
        return (
          <View key={index} style={styles.keywordBox}>
            <View style={styles.row}>
              <Image source={pizzaImages[index % pizzaImages.length]} style={styles.pizzaImg} />
              <Text style={styles.word}>{word}</Text>
            </View>
            {desc && <Text style={styles.desc}>{desc}</Text>}
          </View>
        );
      })}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { padding: SPACING.xl, paddingBottom: 40 },
  keywordBox: { marginBottom: SPACING.lg, padding: SPACING.xl, backgroundColor: COLORS.bgCardElevated, borderRadius: RADIUS.lg, borderWidth: 1, borderColor: COLORS.glassBorder, ...SHADOWS.sm },
  row: { flexDirection: "row", alignItems: "center", marginBottom: 3, marginLeft: 5 },
  word: { ...TYPO.h3, color: COLORS.textPrimary },
  pizzaImg: { width: 28, height: 28, marginRight: 8 },
  desc: { ...TYPO.bodySm, color: COLORS.textSecondary, marginTop: 6 },
});
