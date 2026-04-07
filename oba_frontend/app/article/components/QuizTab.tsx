"use client"

import { useState, useEffect, useRef } from "react"
import { ScrollView, View, Text, TouchableOpacity, StyleSheet, Image, Modal, Animated, Easing } from "react-native"
import { COLORS, RADIUS, SHADOWS, TYPO, SPACING } from "../../../constants/theme"

export default function QuizTab({ quizList, selected, isGraded, isOpen, handleSelect, handleGrade, toggleOpen, alreadySubmitted = false }) {
  const [showResult, setShowResult] = useState(false)

  if (!quizList || quizList.length === 0) {
    return (
      <View style={{ flex: 1, justifyContent: "center", alignItems: "center", paddingTop: 60 }}>
        <Text style={{ ...TYPO.body, color: COLORS.textTertiary }}>퀴즈를 준비 중이에요.</Text>
      </View>
    )
  }

  const confettiAnims = useRef(Array.from({ length: 150 }, () => ({ translateY: new Animated.Value(0), translateX: new Animated.Value(0), rotate: new Animated.Value(0), opacity: new Animated.Value(0), scale: new Animated.Value(0) }))).current
  const sparkleAnims = useRef(Array.from({ length: 30 }, () => ({ scale: new Animated.Value(0), opacity: new Animated.Value(0), rotate: new Animated.Value(0) }))).current
  const burstRings = useRef(Array.from({ length: 3 }, () => ({ scale: new Animated.Value(0), opacity: new Animated.Value(0) }))).current
  const pizzaConfettiAnims = useRef(Array.from({ length: 40 }, () => ({ translateY: new Animated.Value(0), translateX: new Animated.Value(0), rotate: new Animated.Value(0), opacity: new Animated.Value(0), scale: new Animated.Value(0) }))).current

  const pizzaImages = [
    require("../../../assets/pizza/comb.png"),
    require("../../../assets/pizza/hwaa.png"),
    require("../../../assets/pizza/mar.png"),
    require("../../../assets/pizza/pep.png"),
  ]

  const totalCount = quizList.length
  const gradedCount = isGraded.filter((g) => g === true).length
  const correctCount = quizList.reduce((acc, quiz, index) => (selected[index] === quiz.answerIndex ? acc + 1 : acc), 0)

  const triggerConfetti = () => {
    confettiAnims.forEach((a) => { a.translateY.setValue(0); a.translateX.setValue(0); a.rotate.setValue(0); a.opacity.setValue(0); a.scale.setValue(0) })
    sparkleAnims.forEach((a) => { a.scale.setValue(0); a.opacity.setValue(0); a.rotate.setValue(0) })
    burstRings.forEach((a) => { a.scale.setValue(0); a.opacity.setValue(0) })

    const ringAnims = burstRings.map((a, i) => Animated.sequence([Animated.delay(i * 80), Animated.parallel([
      Animated.timing(a.scale, { toValue: 3 + i * 0.5, duration: 1000, easing: Easing.out(Easing.cubic), useNativeDriver: true }),
      Animated.sequence([Animated.timing(a.opacity, { toValue: 0.6, duration: 100, useNativeDriver: true }), Animated.timing(a.opacity, { toValue: 0, duration: 900, useNativeDriver: true })])
    ])]))

    const sparkAnims = sparkleAnims.map((a) => Animated.sequence([Animated.delay(Math.random() * 200), Animated.parallel([
      Animated.spring(a.scale, { toValue: 1 + Math.random() * 0.5, friction: 4, tension: 50, useNativeDriver: true }),
      Animated.sequence([Animated.timing(a.opacity, { toValue: 1, duration: 150, useNativeDriver: true }), Animated.loop(Animated.sequence([Animated.timing(a.opacity, { toValue: 0.3, duration: 400, useNativeDriver: true }), Animated.timing(a.opacity, { toValue: 1, duration: 400, useNativeDriver: true })]), { iterations: 2 }), Animated.timing(a.opacity, { toValue: 0, duration: 300, useNativeDriver: true })]),
      Animated.timing(a.rotate, { toValue: 360 + Math.random() * 360, duration: 2000, easing: Easing.out(Easing.cubic), useNativeDriver: true })
    ])]))

    const confAnims = confettiAnims.map((a, i) => {
      const p = i % 6; let fX, fY, dur, del
      if (p === 0) { const ang = (i / 25) * Math.PI * 2; const d = 180 + Math.random() * 150; fX = Math.cos(ang) * d; fY = Math.sin(ang) * d; dur = 1000 + Math.random() * 500; del = 0 }
      else if (p === 1) { fX = (Math.random() - 0.5) * 250; fY = -250 - Math.random() * 200; dur = 1200 + Math.random() * 600; del = 50 }
      else if (p === 2) { const ang = (i / 25) * Math.PI * 6; const d = (i % 25) * 12 + 100; fX = Math.cos(ang) * d; fY = Math.sin(ang) * d; dur = 1100 + Math.random() * 500; del = (i % 25) * 15 }
      else if (p === 3) { fX = (Math.random() - 0.5) * 500; fY = (Math.random() - 0.5) * 500; dur = 800 + Math.random() * 600; del = Math.random() * 200 }
      else if (p === 4) { const dir = Math.random() > 0.5 ? 1 : -1; fX = dir * (200 + Math.random() * 200); fY = -150 - Math.random() * 150; dur = 1000 + Math.random() * 400; del = Math.random() * 250 }
      else { const ang = Math.random() * Math.PI * 2; const d = 150 + Math.random() * 180; fX = Math.cos(ang) * d; fY = Math.sin(ang) * d; dur = 900 + Math.random() * 500; del = Math.random() * 150 }
      const rr = Math.random() * 3600 - 1800
      return Animated.sequence([Animated.delay(del), Animated.parallel([
        Animated.spring(a.scale, { toValue: 1.5 + Math.random() * 0.8, friction: 2.5, tension: 50, useNativeDriver: true }),
        Animated.timing(a.opacity, { toValue: 1, duration: 150, useNativeDriver: true }),
        Animated.timing(a.translateX, { toValue: fX, duration: dur, easing: Easing.out(Easing.cubic), useNativeDriver: true }),
        Animated.timing(a.translateY, { toValue: fY, duration: dur, easing: Easing.out(Easing.quad), useNativeDriver: true }),
        Animated.timing(a.rotate, { toValue: rr, duration: dur, easing: Easing.linear, useNativeDriver: true })
      ]), Animated.timing(a.opacity, { toValue: 0, duration: 400, useNativeDriver: true })])
    })
    Animated.parallel([...ringAnims, ...sparkAnims, ...confAnims]).start()
  }

  const triggerPizzaConfetti = () => {
    pizzaConfettiAnims.forEach((a) => { a.translateY.setValue(0); a.translateX.setValue(0); a.rotate.setValue(0); a.opacity.setValue(0); a.scale.setValue(0) })
    const anims = pizzaConfettiAnims.map((a, i) => {
      const ang = (i / pizzaConfettiAnims.length) * Math.PI * 2; const d = 150 + Math.random() * 120
      const fX = Math.cos(ang) * d; const fY = Math.sin(ang) * d - 50; const dur = 1200 + Math.random() * 400; const rr = Math.random() * 720 - 360
      return Animated.sequence([Animated.delay(Math.random() * 150), Animated.parallel([
        Animated.spring(a.scale, { toValue: 1, friction: 3, tension: 40, useNativeDriver: true }),
        Animated.timing(a.opacity, { toValue: 1, duration: 100, useNativeDriver: true }),
        Animated.timing(a.translateX, { toValue: fX, duration: dur, easing: Easing.out(Easing.cubic), useNativeDriver: true }),
        Animated.timing(a.translateY, { toValue: fY, duration: dur, easing: Easing.bezier(0.33, 1, 0.68, 1), useNativeDriver: true }),
        Animated.timing(a.rotate, { toValue: rr, duration: dur, easing: Easing.linear, useNativeDriver: true })
      ]), Animated.timing(a.opacity, { toValue: 0, duration: 300, useNativeDriver: true })])
    })
    Animated.parallel(anims).start()
  }

  useEffect(() => {
    if (totalCount > 0 && gradedCount === totalCount && !alreadySubmitted) {
      setShowResult(true)
      if (correctCount === totalCount) { triggerPizzaConfetti() }
    }
  }, [gradedCount, totalCount])

  const getResultContent = () => {
    if (correctCount === totalCount) return { emoji: "🏆", title: "완벽해요!", desc: `모든 문제를 맞히셨네요!\n피자 한 판 드실 자격이 있습니다!` }
    if (correctCount >= totalCount / 2) return { emoji: "👏", title: "잘했어요!", desc: `${totalCount}문제 중 ${correctCount}개를 맞혔어요.\n거의 다 왔어요!` }
    return { emoji: "😓", title: "아쉬워요", desc: `${totalCount}문제 중 ${correctCount}개를 맞혔어요.\n다음엔 더 잘할 수 있어요!` }
  }

  const resultContent = getResultContent()

  return (
    <View style={{ flex: 1 }}>
      <ScrollView showsVerticalScrollIndicator={false} contentContainerStyle={{ padding: SPACING.xl, paddingBottom: 80 }}>
        <Text style={s.header}>Quiz</Text>

        {alreadySubmitted && (
          <View style={s.alreadyBanner}><Text style={s.alreadyText}>이미 풀었던 퀴즈입니다. 오답노트에서 다시 풀 수 있어요.</Text></View>
        )}

        {quizList.map((quiz, qIndex) => {
          const userAnswer = selected[qIndex]; const graded = isGraded[qIndex]; const open = isOpen[qIndex]; const isCorrect = userAnswer === quiz.answerIndex
          return (
            <View key={qIndex} style={s.quizBlock}>
              <Text style={s.question}>{`Q${qIndex + 1}. ${quiz.question}`}</Text>
              {quiz.options.map((opt, oIndex) => {
                const sel = userAnswer === oIndex
                return (
                  <TouchableOpacity key={oIndex} disabled={graded} onPress={() => handleSelect(qIndex, oIndex)}
                    style={[s.option, sel && s.selected,
                      graded && oIndex === quiz.answerIndex && s.optionCorrect,
                      graded && sel && oIndex !== quiz.answerIndex && s.optionWrong,
                    ]}>
                    <Text style={[s.optionText, sel && s.optionTextSelected]}>{opt}</Text>
                  </TouchableOpacity>
                )
              })}

              <TouchableOpacity onPress={() => handleGrade(qIndex)} disabled={graded || selected[qIndex] === undefined}
                style={[s.gradeBtn, (graded || selected[qIndex] === undefined) && s.disabledBtn]}>
                <Text style={s.gradeText}>{graded ? "채점 완료" : "채점하기"}</Text>
              </TouchableOpacity>

              {graded && (
                <View style={s.explanationWrapper}>
                  <TouchableOpacity onPress={() => toggleOpen(qIndex)}>
                    <Image source={open ? require("../../../assets/icons/toggle_1.png") : require("../../../assets/icons/toggle_2.png")} style={s.pizzaIcon} />
                  </TouchableOpacity>
                  {open && (
                    <View style={s.explanationBox}>
                      <Text style={[s.resultText, { color: isCorrect ? COLORS.success : COLORS.error }]}>{isCorrect ? "🎉 정답입니다!" : "❌ 오답입니다!"}</Text>
                      <Text style={s.explanation}>{quiz.explanation}</Text>
                    </View>
                  )}
                </View>
              )}
            </View>
          )
        })}
      </ScrollView>

      <Modal animationType="slide" transparent visible={showResult} onRequestClose={() => setShowResult(false)}>
        <View style={s.modalOverlay}>
          {correctCount === totalCount && pizzaConfettiAnims.map((a, i) => (
            <Animated.View key={`pizza-${i}`} pointerEvents="none" style={[s.pizzaConfetti, { opacity: a.opacity, transform: [{ translateX: a.translateX }, { translateY: a.translateY }, { scale: a.scale }, { rotate: a.rotate.interpolate({ inputRange: [-360, 360], outputRange: ["-360deg", "360deg"] }) }] }]}>
              <Image source={pizzaImages[i % pizzaImages.length]} style={s.pizzaImage} />
            </Animated.View>
          ))}
          {correctCount === totalCount && burstRings.map((a, i) => (
            <Animated.View key={`ring-${i}`} pointerEvents="none" style={[s.burstRing, { opacity: a.opacity, transform: [{ scale: a.scale }], borderColor: i === 0 ? COLORS.secondary : i === 1 ? COLORS.accent : COLORS.primary }]} />
          ))}
          {correctCount === totalCount && sparkleAnims.map((a, i) => {
            const ang = (i / sparkleAnims.length) * Math.PI * 2; const d = 100 + Math.random() * 80
            return (
              <Animated.View key={`sparkle-${i}`} pointerEvents="none" style={[s.sparkle, { left: `${50 + Math.cos(ang) * d}%`, top: `${50 + Math.sin(ang) * d}%`, opacity: a.opacity, transform: [{ scale: a.scale }, { rotate: a.rotate.interpolate({ inputRange: [0, 360], outputRange: ["0deg", "360deg"] }) }] }]}>
                <Text style={s.sparkleText}>✨</Text>
              </Animated.View>
            )
          })}
          {correctCount === totalCount && confettiAnims.map((a, i) => {
            const colors = [COLORS.secondary, COLORS.accent, COLORS.primary, COLORS.success, COLORS.primaryLight, "#FF4081", "#9C27B0", "#00BCD4", "#FFEB3B", "#FF5722"]
            const sz = 10 + (i % 8) * 3; const shp = ["circle", "square", "diamond"][i % 3]; let br = 0
            if (shp === "circle") br = sz / 2; else if (shp === "square") br = 2
            return (
              <Animated.View key={`confetti-${i}`} pointerEvents="none" style={[s.confetti, { backgroundColor: colors[i % colors.length], width: sz, height: sz, borderRadius: br, opacity: a.opacity, transform: [{ translateX: a.translateX }, { translateY: a.translateY }, { scale: a.scale }, { rotate: a.rotate.interpolate({ inputRange: [-1800, 1800], outputRange: ["-1800deg", "1800deg"] }) }, ...(shp === "diamond" ? [{ rotate: "45deg" }] : [])] }]} />
            )
          })}

          <View style={s.modalContent}>
            <Text style={s.modalEmoji}>{resultContent.emoji}</Text>
            <Text style={s.modalTitle}>{resultContent.title}</Text>
            <Text style={s.modalScore}>총 <Text style={{ color: COLORS.primary }}>{correctCount}</Text>개 / {totalCount}개</Text>
            <Text style={s.modalDesc}>{resultContent.desc}</Text>
            <TouchableOpacity style={s.modalCloseBtn} onPress={() => setShowResult(false)}>
              <Text style={s.modalCloseText}>확인</Text>
            </TouchableOpacity>
          </View>
        </View>
      </Modal>
    </View>
  )
}

const s = StyleSheet.create({
  header: { ...TYPO.h1, textAlign: "center", marginBottom: SPACING.xl, color: COLORS.textPrimary },
  alreadyBanner: { backgroundColor: COLORS.primarySurface, padding: SPACING.md, borderRadius: RADIUS.md, marginBottom: SPACING.lg, alignItems: "center", borderWidth: 1, borderColor: COLORS.border },
  alreadyText: { ...TYPO.bodySm, color: COLORS.primaryLight, fontWeight: "600" },
  quizBlock: {
    backgroundColor: COLORS.bgCardElevated, borderRadius: RADIUS.card, padding: SPACING.xl,
    marginBottom: SPACING.xxl, borderWidth: 1, borderColor: COLORS.glassBorder, ...SHADOWS.md,
  },
  question: { ...TYPO.h3, color: COLORS.textPrimary, marginBottom: SPACING.lg },
  option: {
    padding: SPACING.lg, borderWidth: 1.5, borderColor: COLORS.border,
    borderRadius: RADIUS.md, marginBottom: SPACING.sm, backgroundColor: COLORS.bgSecondary,
  },
  optionText: { ...TYPO.label, color: COLORS.textSecondary },
  optionTextSelected: { color: COLORS.primary },
  selected: { borderColor: COLORS.primary, backgroundColor: COLORS.primarySurface },
  optionCorrect: { backgroundColor: COLORS.successSurface, borderColor: COLORS.success },
  optionWrong: { backgroundColor: COLORS.errorSurface, borderColor: COLORS.error },
  gradeBtn: {
    marginTop: SPACING.md, backgroundColor: COLORS.primary, paddingVertical: SPACING.md,
    borderRadius: RADIUS.button,
    shadowColor: COLORS.primary, shadowOffset: { width: 0, height: 4 }, shadowOpacity: 0.3, shadowRadius: 12, elevation: 4,
  },
  gradeText: { ...TYPO.button, color: "#fff", textAlign: "center", fontSize: 14 },
  disabledBtn: { backgroundColor: COLORS.textPlaceholder, shadowOpacity: 0 },
  explanationWrapper: { flexDirection: "row", alignItems: "flex-start", marginTop: SPACING.lg },
  pizzaIcon: { width: 36, height: 36, marginRight: 10 },
  explanationBox: { flex: 1, backgroundColor: COLORS.bgSecondary, borderRadius: RADIUS.md, padding: SPACING.md },
  resultText: { fontWeight: "600", fontSize: 15, marginBottom: 4 },
  explanation: { ...TYPO.bodySm, color: COLORS.textSecondary },

  modalOverlay: { flex: 1, backgroundColor: COLORS.overlay, justifyContent: "center", alignItems: "center" },
  modalContent: {
    width: "80%", backgroundColor: COLORS.bgCardElevated, borderRadius: RADIUS.xxl,
    padding: SPACING.xxxl, alignItems: "center", ...SHADOWS.lg,
    borderWidth: 1, borderColor: COLORS.glassBorder,
  },
  modalEmoji: { fontSize: 50, marginBottom: 10 },
  modalTitle: { ...TYPO.h1, color: COLORS.textPrimary, marginBottom: 10 },
  modalScore: { ...TYPO.h3, color: COLORS.textSecondary, marginBottom: SPACING.lg },
  modalDesc: { ...TYPO.bodySm, textAlign: "center", color: COLORS.textTertiary, marginBottom: SPACING.xxl, lineHeight: 22 },
  modalCloseBtn: {
    backgroundColor: COLORS.primary, paddingVertical: SPACING.md, paddingHorizontal: 30,
    borderRadius: RADIUS.pill,
    shadowColor: COLORS.primary, shadowOffset: { width: 0, height: 4 }, shadowOpacity: 0.3, shadowRadius: 12, elevation: 4,
  },
  modalCloseText: { ...TYPO.button, color: "white" },
  confetti: { position: "absolute", top: "50%", left: "50%" },
  burstRing: { position: "absolute", top: "50%", left: "50%", width: 100, height: 100, marginLeft: -50, marginTop: -50, borderRadius: 50, borderWidth: 3 },
  sparkle: { position: "absolute" },
  sparkleText: { fontSize: 24 },
  pizzaConfetti: { position: "absolute", top: "50%", left: "50%" },
  pizzaImage: { width: 60, height: 60 },
})
