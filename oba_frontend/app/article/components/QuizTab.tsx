// oba_fronted/app/article/components/QuizTab.tsx

"use client"

import { useState, useEffect, useRef } from "react"
import { ScrollView, View, Text, TouchableOpacity, StyleSheet, Image, Modal, Animated, Easing } from "react-native"

export default function QuizTab({ quizList, selected, isGraded, isOpen, handleSelect, handleGrade, toggleOpen, alreadySubmitted = false }) {
  const [showResult, setShowResult] = useState(false)

  if (!quizList || quizList.length === 0) {
    return (
      <View style={{ flex: 1, justifyContent: "center", alignItems: "center", paddingTop: 60 }}>
        <Text style={{ fontSize: 16, color: "#999" }}>퀴즈를 준비 중이에요.</Text>
      </View>
    )
  }

  const confettiAnims = useRef(
    Array.from({ length: 150 }, () => ({
      translateY: new Animated.Value(0),
      translateX: new Animated.Value(0),
      rotate: new Animated.Value(0),
      opacity: new Animated.Value(0),
      scale: new Animated.Value(0),
    })),
  ).current

  const sparkleAnims = useRef(
    Array.from({ length: 30 }, () => ({
      scale: new Animated.Value(0),
      opacity: new Animated.Value(0),
      rotate: new Animated.Value(0),
    })),
  ).current

  const burstRings = useRef(
    Array.from({ length: 3 }, () => ({
      scale: new Animated.Value(0),
      opacity: new Animated.Value(0),
    })),
  ).current

  const pizzaConfettiAnims = useRef(
    Array.from({ length: 40 }, () => ({
      translateY: new Animated.Value(0),
      translateX: new Animated.Value(0),
      rotate: new Animated.Value(0),
      opacity: new Animated.Value(0),
      scale: new Animated.Value(0),
    })),
  ).current

  const pizzaImages = [
    require("../../../assets/pizza/comb.png"),
    require("../../../assets/pizza/hwaa.png"),
    require("../../../assets/pizza/mar.png"),
    require("../../../assets/pizza/pep.png"),
  ]

  const totalCount = quizList.length
  const gradedCount = isGraded.filter((graded) => graded === true).length
  const correctCount = quizList.reduce((acc, quiz, index) => {
    const userAnswer = selected[index]
    return userAnswer === quiz.answerIndex ? acc + 1 : acc
  }, 0)

  const triggerConfetti = () => {
    confettiAnims.forEach((anim) => {
      anim.translateY.setValue(0)
      anim.translateX.setValue(0)
      anim.rotate.setValue(0)
      anim.opacity.setValue(0)
      anim.scale.setValue(0)
    })

    sparkleAnims.forEach((anim) => {
      anim.scale.setValue(0)
      anim.opacity.setValue(0)
      anim.rotate.setValue(0)
    })

    burstRings.forEach((anim) => {
      anim.scale.setValue(0)
      anim.opacity.setValue(0)
    })

    const ringAnimations = burstRings.map((anim, index) =>
      Animated.sequence([
        Animated.delay(index * 80),
        Animated.parallel([
          Animated.timing(anim.scale, {
            toValue: 3 + index * 0.5,
            duration: 1000,
            easing: Easing.out(Easing.cubic),
            useNativeDriver: true,
          }),
          Animated.sequence([
            Animated.timing(anim.opacity, {
              toValue: 0.6,
              duration: 100,
              useNativeDriver: true,
            }),
            Animated.timing(anim.opacity, {
              toValue: 0,
              duration: 900,
              useNativeDriver: true,
            }),
          ]),
        ]),
      ]),
    )

    const sparkleAnimations = sparkleAnims.map((anim, index) => {
      const angle = (index / sparkleAnims.length) * Math.PI * 2
      // const distance = 100 + Math.random() * 80

      return Animated.sequence([
        Animated.delay(Math.random() * 200),
        Animated.parallel([
          Animated.spring(anim.scale, {
            toValue: 1 + Math.random() * 0.5,
            friction: 4,
            tension: 50,
            useNativeDriver: true,
          }),
          Animated.sequence([
            Animated.timing(anim.opacity, {
              toValue: 1,
              duration: 150,
              useNativeDriver: true,
            }),
            Animated.loop(
              Animated.sequence([
                Animated.timing(anim.opacity, {
                  toValue: 0.3,
                  duration: 400,
                  useNativeDriver: true,
                }),
                Animated.timing(anim.opacity, {
                  toValue: 1,
                  duration: 400,
                  useNativeDriver: true,
                }),
              ]),
              { iterations: 2 },
            ),
            Animated.timing(anim.opacity, {
              toValue: 0,
              duration: 300,
              useNativeDriver: true,
            }),
          ]),
          Animated.timing(anim.rotate, {
            toValue: 360 + Math.random() * 360,
            duration: 2000,
            easing: Easing.out(Easing.cubic),
            useNativeDriver: true,
          }),
        ]),
      ])
    })

    const confettiAnimations = confettiAnims.map((anim, index) => {
      const patterns = 6
      const pattern = index % patterns
      let finalX, finalY, duration, delay

      if (pattern === 0) {
        // Circular explosion
        const angle = (index / 25) * Math.PI * 2
        const distance = 180 + Math.random() * 150
        finalX = Math.cos(angle) * distance
        finalY = Math.sin(angle) * distance
        duration = 1000 + Math.random() * 500
        delay = 0
      } else if (pattern === 1) {
        // Fountain upward
        finalX = (Math.random() - 0.5) * 250
        finalY = -250 - Math.random() * 200
        duration = 1200 + Math.random() * 600
        delay = 50
      } else if (pattern === 2) {
        // Spiral
        const angle = (index / 25) * Math.PI * 6
        const distance = (index % 25) * 12 + 100
        finalX = Math.cos(angle) * distance
        finalY = Math.sin(angle) * distance
        duration = 1100 + Math.random() * 500
        delay = (index % 25) * 15
      } else if (pattern === 3) {
        // Wide random burst
        finalX = (Math.random() - 0.5) * 500
        finalY = (Math.random() - 0.5) * 500
        duration = 800 + Math.random() * 600
        delay = Math.random() * 200
      } else if (pattern === 4) {
        // Diagonal streaks
        const direction = Math.random() > 0.5 ? 1 : -1
        finalX = direction * (200 + Math.random() * 200)
        finalY = -150 - Math.random() * 150
        duration = 1000 + Math.random() * 400
        delay = Math.random() * 250
      } else {
        // Radial burst outward
        const angle = Math.random() * Math.PI * 2
        const distance = 150 + Math.random() * 180
        finalX = Math.cos(angle) * distance
        finalY = Math.sin(angle) * distance
        duration = 900 + Math.random() * 500
        delay = Math.random() * 150
      }

      const randomRotation = Math.random() * 3600 - 1800

      return Animated.sequence([
        Animated.delay(delay),
        Animated.parallel([
          Animated.spring(anim.scale, {
            toValue: 1.5 + Math.random() * 0.8,
            friction: 2.5,
            tension: 50,
            useNativeDriver: true,
          }),
          Animated.timing(anim.opacity, {
            toValue: 1,
            duration: 150,
            useNativeDriver: true,
          }),
          Animated.timing(anim.translateX, {
            toValue: finalX,
            duration: duration,
            easing: Easing.out(Easing.cubic),
            useNativeDriver: true,
          }),
          Animated.timing(anim.translateY, {
            toValue: finalY,
            duration: duration,
            easing: Easing.out(Easing.quad),
            useNativeDriver: true,
          }),
          Animated.timing(anim.rotate, {
            toValue: randomRotation,
            duration: duration,
            easing: Easing.linear,
            useNativeDriver: true,
          }),
        ]),
        Animated.timing(anim.opacity, {
          toValue: 0,
          duration: 400,
          useNativeDriver: true,
        }),
      ])
    })

    Animated.parallel([...ringAnimations, ...sparkleAnimations, ...confettiAnimations]).start()
  }

  const triggerPizzaConfetti = () => {
    pizzaConfettiAnims.forEach((anim) => {
      anim.translateY.setValue(0)
      anim.translateX.setValue(0)
      anim.rotate.setValue(0)
      anim.opacity.setValue(0)
      anim.scale.setValue(0)
    })

    const pizzaAnimations = pizzaConfettiAnims.map((anim, index) => {
      const angle = (index / pizzaConfettiAnims.length) * Math.PI * 2
      const distance = 150 + Math.random() * 120
      const finalX = Math.cos(angle) * distance
      const finalY = Math.sin(angle) * distance - 50
      const duration = 1200 + Math.random() * 400
      const randomRotation = Math.random() * 720 - 360

      return Animated.sequence([
        Animated.delay(Math.random() * 150),
        Animated.parallel([
          Animated.spring(anim.scale, {
            toValue: 1,
            friction: 3,
            tension: 40,
            useNativeDriver: true,
          }),
          Animated.timing(anim.opacity, {
            toValue: 1,
            duration: 100,
            useNativeDriver: true,
          }),
          Animated.timing(anim.translateX, {
            toValue: finalX,
            duration: duration,
            easing: Easing.out(Easing.cubic),
            useNativeDriver: true,
          }),
          Animated.timing(anim.translateY, {
            toValue: finalY,
            duration: duration,
            easing: Easing.bezier(0.33, 1, 0.68, 1),
            useNativeDriver: true,
          }),
          Animated.timing(anim.rotate, {
            toValue: randomRotation,
            duration: duration,
            easing: Easing.linear,
            useNativeDriver: true,
          }),
        ]),
        Animated.timing(anim.opacity, {
          toValue: 0,
          duration: 300,
          useNativeDriver: true,
        }),
      ])
    })

    Animated.parallel(pizzaAnimations).start()
  }

  useEffect(() => {
    if (totalCount > 0 && gradedCount === totalCount && !alreadySubmitted) {
      setShowResult(true)
      if (correctCount === totalCount) {
        triggerPizzaConfetti()
      }
    }
  }, [gradedCount, totalCount])

  const getResultContent = () => {
    if (correctCount === totalCount) {
      return {
        emoji: "🏆",
        title: "완벽해요!",
        desc: "모든 문제를 맞히셨네요!\n이건 피자 한 판 드실 자격이 있습니다!! 🍕🎉",
      }
    } else if (correctCount >= totalCount / 2) {
      return {
        emoji: "👏",
        title: "잘했어요!",
        desc: `${totalCount}문제 중 ${correctCount}개를 맞혔어요.\n거의 다 왔어요, 피자 냄새가 나기 시작해요! 🔥🍕`,
      }
    } else {
      return {
        emoji: "😓",
        title: "아쉬워요",
        desc: `${totalCount}문제 중 ${correctCount}개를 맞혔어요.\n다음엔 따끈한 피자에 더 가까워질 거예요! 🍕😊`,
      }
    }
  }

  const resultContent = getResultContent()

  return (
    <View style={{ flex: 1 }}>
      <ScrollView showsVerticalScrollIndicator={false} contentContainerStyle={{ padding: 20, paddingBottom: 80 }}>
        <Text style={styles.header}>Quiz</Text>

        {alreadySubmitted && (
          <View style={{ backgroundColor: "#FFF8E1", padding: 12, borderRadius: 10, marginBottom: 16, alignItems: "center" }}>
            <Text style={{ fontSize: 14, color: "#F57F17", fontWeight: "600" }}>이미 풀었던 퀴즈입니다. 오답노트에서 다시 풀 수 있어요.</Text>
          </View>
        )}

        {quizList.map((quiz, qIndex) => {
          const userAnswer = selected[qIndex]
          const graded = isGraded[qIndex]
          const open = isOpen[qIndex]
          const isCorrect = userAnswer === quiz.answerIndex

          return (
            <View key={qIndex} style={styles.quizBlock}>
              <Text style={styles.question}>{`Q${qIndex + 1}. ${quiz.question}`}</Text>

              {quiz.options.map((opt, oIndex) => {
                const selectedOption = userAnswer === oIndex

                return (
                  <TouchableOpacity
                    key={oIndex}
                    disabled={graded}
                    onPress={() => handleSelect(qIndex, oIndex)}
                    style={[
                      styles.option,
                      selectedOption && styles.selected,
                      graded &&
                        oIndex === quiz.answerIndex && {
                          backgroundColor: "#DFF5CC",
                          borderColor: "#8BC34A",
                        },
                      graded &&
                        selectedOption &&
                        oIndex !== quiz.answerIndex && {
                          backgroundColor: "#FDDCDC",
                          borderColor: "#E57373",
                        },
                    ]}
                  >
                    <Text style={styles.optionText}>{opt}</Text>
                  </TouchableOpacity>
                )
              })}

              <TouchableOpacity
                onPress={() => handleGrade(qIndex)}
                disabled={graded || selected[qIndex] === undefined}
                style={[
                  styles.gradeBtn,
                  graded && styles.disabledBtn,
                  selected[qIndex] === undefined && styles.disabledBtn,
                ]}
              >
                <Text style={styles.gradeText}>{graded ? "채점 완료" : "채점하기"}</Text>
              </TouchableOpacity>

              {graded && (
                <View style={styles.explanationWrapper}>
                  <TouchableOpacity onPress={() => toggleOpen(qIndex)}>
                    <Image
                      source={
                        open
                          ? require("../../../assets/icons/toggle_1.png")
                          : require("../../../assets/icons/toggle_2.png")
                      }
                      style={styles.pizzaIcon}
                    />
                  </TouchableOpacity>

                  {open && (
                    <View style={styles.explanationBox}>
                      <Text style={[styles.resultText, { color: isCorrect ? "#2E7D32" : "#C62828" }]}>
                        {isCorrect ? "🎉 정답입니다!" : "❌ 오답입니다!"}
                      </Text>

                      <Text style={styles.explanation}>{quiz.explanation}</Text>
                    </View>
                  )}
                </View>
              )}
            </View>
          )
        })}
      </ScrollView>

      <Modal animationType="slide" transparent={true} visible={showResult} onRequestClose={() => setShowResult(false)}>
        <View style={styles.modalOverlay}>
          {correctCount === totalCount &&
            pizzaConfettiAnims.map((anim, index) => {
              const pizzaImage = pizzaImages[index % pizzaImages.length]

              return (
                <Animated.View
                  key={`pizza-${index}`}
                  pointerEvents="none"
                  style={[
                    styles.pizzaConfetti,
                    {
                      opacity: anim.opacity,
                      transform: [
                        { translateX: anim.translateX },
                        { translateY: anim.translateY },
                        { scale: anim.scale },
                        {
                          rotate: anim.rotate.interpolate({
                            inputRange: [-360, 360],
                            outputRange: ["-360deg", "360deg"],
                          }),
                        },
                      ],
                    },
                  ]}
                >
                  <Image source={pizzaImage} style={styles.pizzaImage} />
                </Animated.View>
              )
            })}

          {correctCount === totalCount &&
            burstRings.map((anim, index) => (
              <Animated.View
                key={`ring-${index}`}
                pointerEvents="none"
                style={[
                  styles.burstRing,
                  {
                    opacity: anim.opacity,
                    transform: [{ scale: anim.scale }],
                    borderColor: index === 0 ? "#FFD700" : index === 1 ? "#FF1744" : "#00E5FF",
                  },
                ]}
              />
            ))}

          {correctCount === totalCount &&
            sparkleAnims.map((anim, index) => {
              const angle = (index / sparkleAnims.length) * Math.PI * 2
              const distance = 100 + Math.random() * 80
              const left = `${50 + Math.cos(angle) * distance}%`
              const top = `${50 + Math.sin(angle) * distance}%`

              return (
                <Animated.View
                  key={`sparkle-${index}`}
                  pointerEvents="none"
                  style={[
                    styles.sparkle,
                    {
                      left,
                      top,
                      opacity: anim.opacity,
                      transform: [
                        { scale: anim.scale },
                        {
                          rotate: anim.rotate.interpolate({
                            inputRange: [0, 360],
                            outputRange: ["0deg", "360deg"],
                          }),
                        },
                      ],
                    },
                  ]}
                >
                  <Text style={styles.sparkleText}>✨</Text>
                </Animated.View>
              )
            })}

          {correctCount === totalCount &&
            confettiAnims.map((anim, index) => {
              const colors = [
                "#FFD700",
                "#FF1744",
                "#00E5FF",
                "#76FF03",
                "#FF6F00",
                "#E91E63",
                "#9C27B0",
                "#3F51B5",
                "#00BCD4",
                "#FFEB3B",
                "#FF5722",
                "#8BC34A",
                "#FFC107",
                "#00ACC1",
                "#D500F9",
                "#FF4081",
                "#1DE9B6",
                "#FF3D00",
                "#EEFF41",
                "#FF80AB",
              ]
              const confettiColor = colors[index % colors.length]
              const size = 10 + (index % 8) * 3
              const shapes = ["circle", "square", "star", "diamond"]
              const shape = shapes[index % 4]
              let borderRadius = 0

              if (shape === "circle") borderRadius = size / 2
              else if (shape === "square") borderRadius = 2
              else if (shape === "diamond") borderRadius = 0

              return (
                <Animated.View
                  key={`confetti-${index}`}
                  pointerEvents="none"
                  style={[
                    styles.confetti,
                    {
                      backgroundColor: confettiColor,
                      width: size,
                      height: size,
                      borderRadius: borderRadius,
                      opacity: anim.opacity,
                      shadowColor: confettiColor,
                      shadowOffset: { width: 0, height: 0 },
                      shadowOpacity: 1,
                      shadowRadius: 12,
                      transform: [
                        { translateX: anim.translateX },
                        { translateY: anim.translateY },
                        { scale: anim.scale },
                        {
                          rotate: anim.rotate.interpolate({
                            inputRange: [-1800, 1800],
                            outputRange: ["-1800deg", "1800deg"],
                          }),
                        },
                        ...(shape === "diamond" ? [{ rotate: "45deg" }] : []),
                      ],
                    },
                  ]}
                />
              )
            })}

          <View style={styles.modalContent}>
            <Text style={styles.modalEmoji}>{resultContent.emoji}</Text>
            <Text style={styles.modalTitle}>{resultContent.title}</Text>
            <Text style={styles.modalScore}>
              총 <Text style={{ color: "#ff9f00" }}>{correctCount}</Text>개 / {totalCount}개
            </Text>
            <Text style={styles.modalDesc}>{resultContent.desc}</Text>

            <TouchableOpacity style={styles.modalCloseBtn} onPress={() => setShowResult(false)}>
              <Text style={styles.modalCloseText}>확인</Text>
            </TouchableOpacity>
          </View>
        </View>
      </Modal>
    </View>
  )
}

const styles = StyleSheet.create({
  container: { padding: 20 },
  header: {
    fontSize: 22,
    fontWeight: "700",
    textAlign: "center",
    marginBottom: 20,
  },

  quizBlock: {
    backgroundColor: "white",
    borderRadius: 14,
    padding: 16,
    marginBottom: 24,
    shadowColor: "#000",
    shadowOpacity: 0.05,
    shadowRadius: 4,
    elevation: 2,
  },

  question: { fontSize: 16, fontWeight: "600", marginBottom: 14 },

  option: {
    padding: 12,
    borderWidth: 1,
    borderColor: "#eee",
    borderRadius: 8,
    marginBottom: 8,
    backgroundColor: "#fff",
  },

  optionText: { fontSize: 14, color: "#333" },

  selected: {
    borderColor: "#ff9f00",
    backgroundColor: "#fff5e0",
  },

  gradeBtn: {
    marginTop: 10,
    backgroundColor: "#222",
    paddingVertical: 12,
    borderRadius: 8,
  },

  gradeText: {
    color: "#fff",
    textAlign: "center",
    fontWeight: "600",
  },

  disabledBtn: { backgroundColor: "#ccc" },

  explanationWrapper: {
    flexDirection: "row",
    alignItems: "flex-start",
    marginTop: 16,
  },

  pizzaIcon: {
    width: 36,
    height: 36,
    marginRight: 10,
  },

  explanationBox: {
    flex: 1,
    backgroundColor: "#f0f8ff",
    borderRadius: 10,
    padding: 12,
  },

  resultText: { fontWeight: "600", fontSize: 15, marginBottom: 4 },

  explanation: { fontSize: 14, color: "#555", lineHeight: 20 },

  modalOverlay: {
    flex: 1,
    backgroundColor: "rgba(0,0,0,0.5)",
    justifyContent: "center",
    alignItems: "center",
  },
  modalContent: {
    width: "80%",
    backgroundColor: "white",
    borderRadius: 20,
    padding: 30,
    alignItems: "center",
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.25,
    shadowRadius: 4,
    elevation: 5,
  },
  modalEmoji: {
    fontSize: 50,
    marginBottom: 10,
  },
  modalTitle: {
    fontSize: 24,
    fontWeight: "bold",
    marginBottom: 10,
    color: "#333",
  },
  modalScore: {
    fontSize: 18,
    fontWeight: "600",
    marginBottom: 16,
    color: "#555",
  },
  modalDesc: {
    fontSize: 15,
    textAlign: "center",
    color: "#666",
    marginBottom: 24,
    lineHeight: 22,
  },
  modalCloseBtn: {
    backgroundColor: "#ff9f00",
    paddingVertical: 12,
    paddingHorizontal: 30,
    borderRadius: 25,
  },
  modalCloseText: {
    color: "white",
    fontWeight: "bold",
    fontSize: 16,
  },
  confetti: {
    position: "absolute",
    top: "50%",
    left: "50%",
  },
  burstRing: {
    position: "absolute",
    top: "50%",
    left: "50%",
    width: 100,
    height: 100,
    marginLeft: -50,
    marginTop: -50,
    borderRadius: 50,
    borderWidth: 3,
  },
  sparkle: {
    position: "absolute",
  },
  sparkleText: {
    fontSize: 24,
    textShadowColor: "#FFD700",
    textShadowOffset: { width: 0, height: 0 },
    textShadowRadius: 10,
  },
  pizzaConfetti: {
    position: "absolute",
    top: "50%",
    left: "50%",
  },
  pizzaImage: {
    width: 60,
    height: 60,
  },
})