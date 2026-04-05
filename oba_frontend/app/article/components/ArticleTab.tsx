// oba_fronted/app/article/components/ArticleTab.tsx

// oba_fronted/app/article/components/ArticleTab.tsx

import { useState, useEffect } from "react";
import { View, Text, ScrollView, StyleSheet, Platform, Image, TouchableOpacity } from "react-native";

// [이미지 경로] assets/icons 폴더가 프로젝트 최상위에 위치
const iconExpanded = require("../../../assets/icons/toggle_1.png");
const iconCollapsed = require("../../../assets/icons/toggle_2.png");

// 1. 이미지 비율 자동 조절 컴포넌트
const AutoHeightImage = ({ uri }) => {
  const [aspectRatio, setAspectRatio] = useState(1.5); // 기본비율

  useEffect(() => {
    if (uri) {
      Image.getSize(
        uri,
        (width, height) => {
          if (width > 0 && height > 0) {
            setAspectRatio(width / height);
          }
        },
        (error) => {
          console.log("Image size load failed:", error);
        }
      );
    }
  }, [uri]);

  return (
    <View style={styles.imageContainer}>
      <Image
        source={{ uri }}
        style={[styles.contentImage, { aspectRatio }]}
        resizeMode="contain"
      />
    </View>
  );
};

export default function ArticleTab({ article, onMoveToQuiz }) {
  // 1. 토글 상태 관리
  const [isExpanded, setIsExpanded] = useState(false);

  // 2. 데이터 안전장치 (백엔드 DTO 필드에 맞게 수정)
  // categoryName은 문자열 배열 (예: ["artificial-intelligence", "generative-ai"])
  const categoryList = (article.categoryName || []).map((c: string) =>
    c.replace(/-/g, " ").replace(/\b\w/g, (l: string) => l.toUpperCase())
  );
  // summary: summaryBullets 배열을 문자열로 합침
  const bullets = article.summaryBullets || article.summary_bullets || [];
  const summaryText = Array.isArray(bullets) && bullets.length > 0
    ? bullets.join("\n")
    : (typeof article.summary === "string" ? article.summary : null);
  const subtitles = article.subtitle || [];
  // content가 1차원 문자열 배열이면 하나의 섹션으로 감싸기
  const rawContent = article.content || [];
  const contents = rawContent.length > 0 && !Array.isArray(rawContent[0])
    ? [rawContent]
    : rawContent;

  /**
   * 본문 아이템 렌더링 함수
   */
  const renderContentItem = (line, index, olIndex = 0) => {
    const key = `content-${index}`;

    if (typeof line !== "string") {
      return (
        <Text key={key} style={styles.content}>
          {String(line)}
        </Text>
      );
    }

    // 1. 이미지 처리 (<img>URL)
    if (line.startsWith("<img>")) {
      const imageUrl = line.replace("<img>", "").trim();
      return <AutoHeightImage key={key} uri={imageUrl} />;
    }

    // 2. 순서 없는 리스트 (<ul>)
    if (line.startsWith("<ul>")) {
      const listText = line.replace("<ul>", "").trim();
      return (
        <View key={key} style={styles.listItemContainer}>
          <Text style={styles.bulletPoint}>•</Text>
          <Text style={styles.listItemText}>{listText}</Text>
        </View>
      );
    }

    // 3. 순서 있는 리스트 (<ol>)
    if (line.startsWith("<ol>")) {
      const listText = line.replace("<ol>", "").trim();
      return (
        <View key={key} style={styles.listItemContainer}>
          <Text style={styles.numberPoint}>{olIndex}.</Text>
          <Text style={styles.listItemText}>{listText}</Text>
        </View>
      );
    }

    // 4. 일반 텍스트
    return (
      <Text key={key} style={styles.content}>
        {line}
      </Text>
    );
  };

  return (
    <ScrollView contentContainerStyle={styles.scrollContainer} showsVerticalScrollIndicator={false}>
      {/* --- 헤더 --- */}
      <View style={styles.headerContainer}>
        <View style={styles.categoryWrapper}>
          <ScrollView horizontal={true} showsHorizontalScrollIndicator={false}>
            {categoryList.map((cat, idx) => (
              <View key={idx} style={styles.categoryChip}>
                <Text style={styles.categoryText}>{cat}</Text>
              </View>
            ))}
          </ScrollView>
        </View>

        <Text style={styles.title}>{article.title}</Text>
        {/* ← 메타 정보: publishTime · servingDate 로 교체 */}
        <Text style={styles.meta}>
          {article.publishTime} · {article.servingDate}
        </Text>
      </View>

      {/* --- AI 요약 --- */}
      {summaryText && (
        <View style={styles.aiCard}>
          <TouchableOpacity
            activeOpacity={0.7}
            onPress={() => setIsExpanded(!isExpanded)}
            style={styles.aiHeader}
          >
            <Text style={styles.aiTitle}>
              {isExpanded ? "AI 요약 접기" : "AI 요약 보기"}
            </Text>
            <Image
              source={isExpanded ? iconExpanded : iconCollapsed}
              style={styles.toggleIcon}
              resizeMode="contain"
            />
          </TouchableOpacity>

          {isExpanded && (
            <View style={styles.aiBody}>
              <Text style={styles.aiText}>{summaryText}</Text>
            </View>
          )}
        </View>
      )}

      {/* --- 본문 영역 (카드 스타일 적용) --- */}
      <View style={styles.contentCard}>
        {contents.map((sectionLines, index) => {
          const subTitle = subtitles[index];
          const showSubTitle = subTitle && subTitle !== "nosubtitle";

          // <ol> 번호 계산 로직
          let olCounter = 0;

          return (
            <View key={index} style={styles.sectionBlock}>
              {/* 소제목 */}
              {showSubTitle && <Text style={styles.sectionTitle}>{subTitle}</Text>}

              {/* 본문 내용 매핑 */}
              {Array.isArray(sectionLines) ? (
                sectionLines.map((line, lineIdx) => {
                  if (typeof line === "string" && line.startsWith("<ol>")) {
                    olCounter += 1;
                    return renderContentItem(line, lineIdx, olCounter);
                  } else {
                    olCounter = 0;
                    return renderContentItem(line, lineIdx);
                  }
                })
              ) : (
                <Text style={styles.content}>{sectionLines}</Text>
              )}
            </View>
          );
        })}

        {/* --- 퀴즈 풀러 가기 버튼 --- */}
        <View style={styles.buttonContainer}>
          <TouchableOpacity
            style={styles.quizButton}
            onPress={onMoveToQuiz}
            activeOpacity={0.8}
          >
            <Text style={styles.quizButtonText}>퀴즈 풀러 가기 →</Text>
          </TouchableOpacity>
        </View>
      </View>

      <View style={{ height: 40 }} />
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  scrollContainer: {
    backgroundColor: "#F5F6F8",
    flexGrow: 1,
  },

  // --- 헤더 스타일 ---
  headerContainer: {
    paddingHorizontal: 20,
    paddingTop: 24,
    paddingBottom: 20,
  },
  categoryWrapper: { marginBottom: 10 },
  categoryChip: {
    backgroundColor: "rgba(0,0,0,0.05)",
    paddingHorizontal: 10,
    paddingVertical: 5,
    borderRadius: 6,
    marginRight: 8,
  },
  categoryText: { color: "#555", fontSize: 13, fontWeight: "600" },
  title: { fontSize: 22, fontWeight: "bold", color: "#191F28", lineHeight: 30, marginBottom: 6 },
  meta: { fontSize: 13, color: "#8B95A1" },

  // --- AI 요약 카드 스타일 ---
  aiCard: {
    backgroundColor: "#FFFFFF",
    marginHorizontal: 16,
    marginBottom: 24,
    borderRadius: 16,
    overflow: "hidden",
    ...Platform.select({
      ios: { shadowColor: "#000", shadowOffset: { width: 0, height: 2 }, shadowOpacity: 0.03, shadowRadius: 8 },
      android: { elevation: 2 },
    }),
  },
  aiHeader: { flexDirection: "row", justifyContent: "space-between", alignItems: "center", padding: 16, backgroundColor: "#F9FAFB" },
  aiTitle: { fontSize: 15, fontWeight: "700", color: "#4B6EF5" },
  toggleIcon: { width: 35, height: 35 },
  aiBody: { padding: 16, paddingTop: 0, backgroundColor: "#F9FAFB" },
  aiText: { fontSize: 14, lineHeight: 22, color: "#333D4B" },

  // --- 본문 카드 스타일 ---
  contentCard: {
    backgroundColor: "#FFFFFF",
    marginHorizontal: 16,
    borderRadius: 20,
    padding: 24,
    ...Platform.select({
      ios: {
        shadowColor: "#000",
        shadowOffset: { width: 0, height: 4 },
        shadowOpacity: 0.05,
        shadowRadius: 10,
      },
      android: {
        elevation: 3,
      },
    }),
  },

  sectionBlock: { marginBottom: 24 },

  // 1. 소제목
  sectionTitle: {
    fontSize: 20,
    fontWeight: "700",
    color: "#191F28",
    marginBottom: 12,
    marginTop: 8,
  },

  // 2. 리스트 아이템
  listItemContainer: {
    flexDirection: "row",
    marginBottom: 8,
    paddingLeft: 4,
  },
  bulletPoint: {
    fontSize: 15,
    lineHeight: 26,
    color: "#333D4B",
    marginRight: 8,
    fontWeight: "bold",
  },
  numberPoint: {
    fontSize: 15,
    lineHeight: 26,
    color: "#333D4B",
    marginRight: 8,
    fontWeight: "bold",
  },
  listItemText: {
    flex: 1,
    fontSize: 15,
    lineHeight: 26,
    color: "#333D4B",
    fontWeight: "500",
  },

  // 3. 본문 텍스트
  content: {
    fontSize: 16,
    lineHeight: 26,
    color: "#333D4B",
    letterSpacing: -0.2,
    marginBottom: 12,
  },

  // 이미지 스타일
  imageContainer: {
    marginVertical: 12,
    alignItems: "center",
    borderRadius: 8,
    overflow: "hidden",
    width: "100%",
  },
  contentImage: {
    width: "100%",
    backgroundColor: "#eee",
  },

  // --- 퀴즈 버튼 스타일 ---
  buttonContainer: {
    paddingHorizontal: 7,
    marginTop: 5,
  },
  quizButton: {
    backgroundColor: "#4B6EF5",
    paddingVertical: 12,
    borderRadius: 10,
    alignItems: "center",
    justifyContent: "center",
    ...Platform.select({
      ios: {
        shadowColor: "#4B6EF5",
        shadowOffset: { width: 0, height: 4 },
        shadowOpacity: 0.3,
        shadowRadius: 8,
      },
      android: { elevation: 4 },
    }),
  },
  quizButtonText: {
    color: "#FFFFFF",
    fontSize: 14,
    fontWeight: "700",
  },
});
