// oba_fronted/app/article/components/KeywordTab.tsx

import { View, Text, StyleSheet, ScrollView, Image } from "react-native";

// 🍕 pizza 이미지 4개 불러오기
const pizzaImages = [
  require("../../../assets/pizza/comb.png"),
  require("../../../assets/pizza/hwaa.png"),
  require("../../../assets/pizza/mar.png"),
  require("../../../assets/pizza/pep.png"),
];

export default function KeywordTab({ keywords = [] }) {
  if (!keywords || !Array.isArray(keywords) || keywords.length === 0) {
    return (
      <ScrollView contentContainerStyle={{ padding: 20, alignItems: "center", paddingTop: 60 }}>
        <Text style={{ fontSize: 16, color: "#999" }}>키워드를 준비 중이에요.</Text>
      </ScrollView>
    );
  }
  return (
    <ScrollView contentContainerStyle={styles.container}>
      {keywords.map((item: any, index: number) => {
        const word = typeof item === "string" ? item : item.keyword || "";
        const desc = typeof item === "object" && item.description ? item.description : null;
        return (
          <View key={index} style={styles.keywordBox}>
            <View style={styles.row}>
              <Image source={pizzaImages[index % pizzaImages.length]} style={styles.pizzaImg} />
              <Text style={styles.word}>{word}</Text>
            </View>
            {desc && <Text style={{ fontSize: 13, color: "#666", marginTop: 6, lineHeight: 19 }}>{desc}</Text>}
          </View>
        );
      })}
    </ScrollView>
  );
}


const styles = StyleSheet.create({
  scrollView: { flex: 1 },
  container: { padding: 20, paddingBottom: 40 },
  keywordBox: {
    marginBottom: 18,
    padding: 16,
    backgroundColor: "#fff",
    borderRadius: 14,
    shadowColor: "#000",
    shadowOpacity: 0.07,
    shadowRadius: 6,
    shadowOffset: { width: 0, height: 3 },
    elevation: 3,
  },
  row: {
    flexDirection: "row",
    alignItems: "center",
    marginBottom: 3,
    marginLeft: 5,
  },
  word: {
    fontSize: 16,
    fontWeight: "700",
    color: "#333",
  },
  pizzaImg: {
    width: 23,
    height: 23,
    marginRight: 6,
  },
});
