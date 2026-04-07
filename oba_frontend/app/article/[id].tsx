// oba_fronted/app/article/[id].tsx
import { useState, useEffect, useRef } from "react";
import { View, Text, ActivityIndicator, Alert } from "react-native";
import { useRouter, useLocalSearchParams } from "expo-router";
import TabBar from "./components/TabBar";
import ArticleTab from "./components/ArticleTab";
import SummaryTab from "./components/SummaryTab";
import KeywordTab from "./components/KeywordTab";
import QuizTab from "./components/QuizTab";
import { apiClient } from "../../src/api/apiClient";
import { COLORS } from "../../constants/theme";

export default function ArticleDetail() {
  const router = useRouter();
  const { id, retry } = useLocalSearchParams();
  const [activeTab, setActiveTab] = useState("기사");
  const [article, setArticle] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  const [selected, setSelected] = useState<Record<number, number>>({});
  const [isGraded, setIsGraded] = useState<boolean[]>([]);
  const [isOpen, setIsOpen] = useState<Record<number, boolean>>({});
  const hasSubmitted = useRef(false);

  useEffect(() => {
    if (!id) return;
    const fetchArticle = async () => {
      try {
        const res = await apiClient.get(`/api/articles/${id}`);
        const data = res.data;
        setArticle(data);
        const quizzes = data.quizzes || [];
        const prevResults: boolean[] | null = data.myQuizResults;
        const isRetry = retry === "true";
        if (!isRetry && prevResults && prevResults.length === quizzes.length && prevResults.length > 0) {
          const restoredSelected: Record<number, number> = {};
          const restoredGraded: boolean[] = [];
          const restoredOpen: Record<number, boolean> = {};
          quizzes.forEach((quiz: any, i: number) => {
            restoredGraded.push(true);
            restoredOpen[i] = true;
            if (prevResults[i]) { restoredSelected[i] = quiz.answerIndex; }
            else { for (let j = 0; j < quiz.options.length; j++) { if (j !== quiz.answerIndex) { restoredSelected[i] = j; break; } } }
          });
          setSelected(restoredSelected); setIsGraded(restoredGraded); setIsOpen(restoredOpen); hasSubmitted.current = true;
        } else { setIsGraded(new Array(quizzes.length).fill(false)); }
      } catch (err) {
        console.error("기사 상세 로딩 실패:", err);
        Alert.alert("오류", "기사를 불러올 수 없습니다."); router.back();
      } finally { setLoading(false); }
    };
    fetchArticle();
  }, [id]);

  useEffect(() => {
    if (!article || hasSubmitted.current) return;
    const quizzes = article.quizzes || [];
    if (quizzes.length === 0) return;
    const allGraded = isGraded.length === quizzes.length && isGraded.every(Boolean);
    if (!allGraded) return;
    const results = quizzes.map((quiz: any, i: number) => selected[i] === quiz.answerIndex);
    hasSubmitted.current = true;
    apiClient.post("/api/quiz/result", { articleId: id, results }).then(() => {
      console.log("퀴즈 결과 저장 완료");
    }).catch((err: any) => { console.error("퀴즈 결과 저장 실패:", err); });
  }, [isGraded]);

  if (loading) {
    return (
      <View style={{ flex: 1, justifyContent: "center", alignItems: "center", backgroundColor: COLORS.bgPrimary }}>
        <ActivityIndicator size="large" color={COLORS.primary} />
      </View>
    );
  }
  if (!article) return null;

  const handleSelect = (q: number, o: number) => setSelected(prev => ({ ...prev, [q]: o }));
  const handleGrade = (qIndex: number) => {
    setIsGraded(prev => { const updated = [...prev]; updated[qIndex] = true; return updated; });
    setIsOpen(prev => ({ ...prev, [qIndex]: true }));
  };
  const toggleOpen = (qIndex: number) => setIsOpen(prev => ({ ...prev, [qIndex]: !prev[qIndex] }));

  return (
    <View style={{ flex: 1, backgroundColor: COLORS.bgPrimary, paddingTop: 10 }}>
      <TabBar activeTab={activeTab} setActiveTab={setActiveTab} goHome={() => router.push("/")} />
      {activeTab === "기사" && <ArticleTab article={article} onMoveToQuiz={() => setActiveTab("퀴즈")} />}
      {activeTab === "요약" && <SummaryTab summary={article.summary ?? null} summaryBullets={article.summaryBullets ?? null} />}
      {activeTab === "키워드" && <KeywordTab keywords={article.keywords ?? []} />}
      {activeTab === "퀴즈" && (
        <QuizTab quizList={article.quizzes ?? []} selected={selected} isGraded={isGraded} isOpen={isOpen}
          handleSelect={hasSubmitted.current ? () => {} : handleSelect}
          handleGrade={hasSubmitted.current ? () => {} : handleGrade}
          toggleOpen={toggleOpen} alreadySubmitted={hasSubmitted.current} />
      )}
    </View>
  );
}
