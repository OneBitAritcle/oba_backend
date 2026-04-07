import { useState, useEffect } from "react";
import { View, Text, ScrollView, StyleSheet, Image, TouchableOpacity } from "react-native";
import { COLORS, RADIUS, SHADOWS, TYPO, SPACING } from "../../../constants/theme";

const iconExpanded = require("../../../assets/icons/toggle_1.png");
const iconCollapsed = require("../../../assets/icons/toggle_2.png");

const AutoHeightImage = ({ uri }) => {
  const [aspectRatio, setAspectRatio] = useState(1.5);
  useEffect(() => {
    if (uri) { Image.getSize(uri, (w, h) => { if (w > 0 && h > 0) setAspectRatio(w / h); }, () => {}); }
  }, [uri]);
  return (
    <View style={styles.imageContainer}>
      <Image source={{ uri }} style={[styles.contentImage, { aspectRatio }]} resizeMode="contain" />
    </View>
  );
};

export default function ArticleTab({ article, onMoveToQuiz }) {
  const [isExpanded, setIsExpanded] = useState(false);
  const categoryList = (article.categoryName || []).map((c: string) => c.replace(/-/g, " ").replace(/\b\w/g, (l: string) => l.toUpperCase()));
  const bullets = article.summaryBullets || article.summary_bullets || [];
  const summaryText = Array.isArray(bullets) && bullets.length > 0 ? bullets.join("\n") : (typeof article.summary === "string" ? article.summary : null);
  const subtitles = article.subtitle || [];
  const rawContent = article.content || [];
  const contents = rawContent.length > 0 && !Array.isArray(rawContent[0]) ? [rawContent] : rawContent;

  const renderContentItem = (line, index, olIndex = 0) => {
    const key = `content-${index}`;
    if (typeof line !== "string") return <Text key={key} style={styles.content}>{String(line)}</Text>;
    if (line.startsWith("<img>")) return <AutoHeightImage key={key} uri={line.replace("<img>", "").trim()} />;
    if (line.startsWith("<ul>")) return (<View key={key} style={styles.listItemContainer}><Text style={styles.bulletPoint}>•</Text><Text style={styles.listItemText}>{line.replace("<ul>", "").trim()}</Text></View>);
    if (line.startsWith("<ol>")) return (<View key={key} style={styles.listItemContainer}><Text style={styles.numberPoint}>{olIndex}.</Text><Text style={styles.listItemText}>{line.replace("<ol>", "").trim()}</Text></View>);
    return <Text key={key} style={styles.content}>{line}</Text>;
  };

  return (
    <ScrollView contentContainerStyle={styles.scrollContainer} showsVerticalScrollIndicator={false}>
      <View style={styles.headerContainer}>
        <View style={styles.categoryWrapper}>
          <ScrollView horizontal showsHorizontalScrollIndicator={false}>
            {categoryList.map((cat, idx) => (
              <View key={idx} style={styles.categoryChip}><Text style={styles.categoryText}>{cat}</Text></View>
            ))}
          </ScrollView>
        </View>
        <Text style={styles.title}>{article.title}</Text>
        <Text style={styles.meta}>{article.servingDate}</Text>
      </View>

      {summaryText && (
        <View style={styles.aiCard}>
          <TouchableOpacity activeOpacity={0.7} onPress={() => setIsExpanded(!isExpanded)} style={styles.aiHeader}>
            <Text style={styles.aiTitle}>{isExpanded ? "AI 요약 접기" : "AI 요약 보기"}</Text>
            <Image source={isExpanded ? iconExpanded : iconCollapsed} style={styles.toggleIcon} resizeMode="contain" />
          </TouchableOpacity>
          {isExpanded && (<View style={styles.aiBody}><Text style={styles.aiText}>{summaryText}</Text></View>)}
        </View>
      )}

      <View style={styles.contentCard}>
        {contents.map((sectionLines, index) => {
          const subTitle = subtitles[index];
          const showSubTitle = subTitle && subTitle !== "nosubtitle";
          let olCounter = 0;
          return (
            <View key={index} style={styles.sectionBlock}>
              {showSubTitle && <Text style={styles.sectionTitle}>{subTitle}</Text>}
              {Array.isArray(sectionLines) ? sectionLines.map((line, lineIdx) => {
                if (typeof line === "string" && line.startsWith("<ol>")) { olCounter += 1; return renderContentItem(line, lineIdx, olCounter); }
                else { olCounter = 0; return renderContentItem(line, lineIdx); }
              }) : <Text style={styles.content}>{sectionLines}</Text>}
            </View>
          );
        })}
        <View style={styles.buttonContainer}>
          <TouchableOpacity style={styles.quizButton} onPress={onMoveToQuiz} activeOpacity={0.8}>
            <Text style={styles.quizButtonText}>퀴즈 풀러 가기 →</Text>
          </TouchableOpacity>
        </View>
      </View>
      <View style={{ height: 40 }} />
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  scrollContainer: { backgroundColor: "transparent", flexGrow: 1 },
  headerContainer: { paddingHorizontal: SPACING.xl, paddingTop: SPACING.xxl, paddingBottom: SPACING.xl },
  categoryWrapper: { marginBottom: 10 },
  categoryChip: {
    backgroundColor: COLORS.primarySurface, paddingHorizontal: 12, paddingVertical: 6,
    borderRadius: RADIUS.pill, marginRight: SPACING.sm, borderWidth: 1, borderColor: COLORS.primary + "30",
  },
  categoryText: { color: COLORS.primaryLight, fontSize: 13, fontWeight: "600" },
  title: { ...TYPO.h1, color: COLORS.textPrimary, lineHeight: 34, marginBottom: SPACING.sm },
  meta: { ...TYPO.caption, color: COLORS.textTertiary },

  aiCard: {
    backgroundColor: COLORS.bgCardElevated, marginHorizontal: SPACING.lg, marginBottom: SPACING.xxl,
    borderRadius: RADIUS.lg, overflow: "hidden", borderWidth: 1, borderColor: COLORS.glassBorder, ...SHADOWS.sm,
  },
  aiHeader: { flexDirection: "row", justifyContent: "space-between", alignItems: "center", padding: SPACING.lg, backgroundColor: COLORS.primarySurface },
  aiTitle: { ...TYPO.label, color: COLORS.primaryLight },
  toggleIcon: { width: 35, height: 35 },
  aiBody: { padding: SPACING.lg, paddingTop: 0, backgroundColor: COLORS.primarySurface },
  aiText: { ...TYPO.bodySm, color: COLORS.textSecondary },

  contentCard: {
    backgroundColor: COLORS.bgCardElevated, marginHorizontal: SPACING.lg,
    borderRadius: RADIUS.xl, padding: SPACING.xxl, borderWidth: 1, borderColor: COLORS.glassBorder, ...SHADOWS.md,
  },
  sectionBlock: { marginBottom: SPACING.xxl },
  sectionTitle: { ...TYPO.h2, color: COLORS.textPrimary, marginBottom: SPACING.md, marginTop: SPACING.sm },
  listItemContainer: { flexDirection: "row", marginBottom: SPACING.sm, paddingLeft: 4 },
  bulletPoint: { fontSize: 15, lineHeight: 26, color: COLORS.textSecondary, marginRight: 8, fontWeight: "bold" },
  numberPoint: { fontSize: 15, lineHeight: 26, color: COLORS.textSecondary, marginRight: 8, fontWeight: "bold" },
  listItemText: { flex: 1, fontSize: 15, lineHeight: 26, color: COLORS.textSecondary, fontWeight: "500" },
  content: { ...TYPO.body, color: COLORS.textSecondary, letterSpacing: -0.2, lineHeight: 28, marginBottom: SPACING.lg },
  imageContainer: { marginVertical: SPACING.md, alignItems: "center", borderRadius: RADIUS.sm, overflow: "hidden", width: "100%" },
  contentImage: { width: "100%", backgroundColor: COLORS.bgSecondary },

  buttonContainer: { paddingHorizontal: 7, marginTop: 5 },
  quizButton: {
    backgroundColor: COLORS.primary, paddingVertical: 14, borderRadius: RADIUS.button,
    alignItems: "center", justifyContent: "center",
    shadowColor: COLORS.primary, shadowOffset: { width: 0, height: 4 }, shadowOpacity: 0.3, shadowRadius: 8, elevation: 4,
  },
  quizButtonText: { ...TYPO.button, color: "#FFFFFF", fontSize: 14 },
});
