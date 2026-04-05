// import { SafeAreaView } from "react-native-safe-area-context";
// import { BlurView } from "expo-blur";
// import { View, Text, TouchableOpacity, StyleSheet } from "react-native";

// export default function TabBar({ activeTab, setActiveTab, goHome }) {
//   return (
//     <SafeAreaView
//       edges={["top"]} 
//       style={{
//         backgroundColor: "transparent",
//       }}
//     >
//       <View style={{ paddingTop: 40 }}>
//         <BlurView
//           intensity={20}
//           tint="light"
//           style={styles.blurBar}
//         >
//           <TouchableOpacity onPress={goHome} style={styles.backBtn}>
//             <Text style={styles.backText}>{"<"}</Text>
//           </TouchableOpacity>

//           {["기사", "요약", "키워드", "퀴즈"].map((tab) => (
//             <TouchableOpacity
//               key={tab}
//               onPress={() => setActiveTab(tab)}
//               style={styles.tabBtn}
//             >
//               <Text
//                 style={[
//                   styles.tabText,
//                   activeTab === tab && styles.tabTextActive,
//                 ]}
//               >
//                 {tab}
//               </Text>
//             </TouchableOpacity>
//           ))}
//         </BlurView>
//       </View>
//     </SafeAreaView>
//   );
// }

// const styles = StyleSheet.create({
//   blurBar: {
//     height: 48,                    // 블러는 상단바 높이만
//     flexDirection: "row",
//     alignItems: "center",
//     paddingHorizontal: 12,
//     backgroundColor: "rgba(255,255,255,0.25)",
//     overflow: "hidden",
//     borderBottomWidth: StyleSheet.hairlineWidth,
//     borderColor: "rgba(255,255,255,0.3)",
//   },

//   backBtn: {
//     paddingRight: 10,
//   },
//   backText: {
//     fontSize: 20,
//     fontWeight: "600",
//   },

//   tabBtn: {
//     paddingHorizontal: 12,
//   },
//   tabText: {
//     fontSize: 15,
//     color: "#888",
//   },
//   tabTextActive: {
//     color: "#222",
//     fontWeight: "700",
//   },
// });

// oba_fronted/app/article/components/TabBar.tsx

// 제안: 아이폰 스타일의 슬라이딩 탭바
import { SafeAreaView } from "react-native-safe-area-context";
import { BlurView } from "expo-blur";
import { View, Text, TouchableOpacity, StyleSheet, Platform } from "react-native";

export default function TabBar({ activeTab, setActiveTab, goHome }) {
  // '요약' 제거하고 3개 탭만 유지
  const tabs = ["기사", "키워드", "퀴즈"];

  return (
    <View style={styles.container}>
      {/* 배경에 블러 효과 적용 */}
      <BlurView intensity={30} tint="light" style={styles.blurBar}>
        <SafeAreaView edges={["top"]} style={styles.safeArea}>
          <View style={styles.innerContainer}>
            
            {/* 1. 뒤로가기 버튼 */}
            <TouchableOpacity 
              onPress={goHome} 
              style={styles.backBtn}
              activeOpacity={0.6}
            >
              <Text style={styles.backText}>←</Text>
            </TouchableOpacity>

            {/* 2. 탭 리스트 (캡슐 스타일) */}
            <View style={styles.tabGroup}>
              {tabs.map((tab) => {
                const isActive = activeTab === tab;
                return (
                  <TouchableOpacity
                    key={tab}
                    onPress={() => setActiveTab(tab)}
                    style={[
                      styles.tabBtn,
                      isActive && styles.tabBtnActive, // 활성 상태 스타일
                    ]}
                    activeOpacity={0.8}
                  >
                    <Text
                      style={[
                        styles.tabText,
                        isActive && styles.tabTextActive, // 활성 텍스트 스타일
                      ]}
                    >
                      {tab}
                    </Text>
                  </TouchableOpacity>
                );
              })}
            </View>

            {/* 오른쪽 여백 밸런스 (뒤로가기 버튼만큼 공간 확보) */}
            <View style={styles.dummySpace} />
            
          </View>
        </SafeAreaView>
      </BlurView>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    // 상단 고정 등을 위해 필요 시 설정
    zIndex: 10,
  },
  blurBar: {
    // 전체 너비와 하단 경계선
    width: "100%",
    borderBottomWidth: 1,
    borderColor: "rgba(0,0,0,0.05)", // 아주 연한 경계선
  },
  safeArea: {
    backgroundColor: "transparent",
  },
  innerContainer: {
    height: 54, // 탭바 높이 살짝 증가 (터치하기 편하게)
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    paddingHorizontal: 16,
  },

  // --- 뒤로가기 버튼 ---
  backBtn: {
    width: 40,
    height: 40,
    justifyContent: "center",
    alignItems: "flex-start", // 왼쪽 정렬
  },
  backText: {
    fontSize: 26, // 화살표 크기 키움
    fontWeight: "400",
    color: "#191F28",
    marginTop: -4, // 폰트 특성상 수직 중앙 맞춤 보정
  },

  // --- 탭 그룹 ---
  tabGroup: {
    flexDirection: "row",
    gap: 4, // 탭 사이 간격
    backgroundColor: "#F2F4F6", // 탭 그룹 전체 배경 (연한 회색 파이프)
    padding: 4,
    borderRadius: 25, // 둥근 모서리
  },

  // --- 개별 탭 버튼 ---
  tabBtn: {
    paddingVertical: 6,
    paddingHorizontal: 14,
    borderRadius: 20, // 캡슐 모양
  },
  // [Active] 선택되었을 때 스타일 (검은색 캡슐)
  tabBtnActive: {
    backgroundColor: "#FFFFFF", // 흰색 배경 (혹은 검정색 #191F28)
    // 그림자 효과
    ...Platform.select({
      ios: {
        shadowColor: "#000",
        shadowOffset: { width: 0, height: 1 },
        shadowOpacity: 0.1,
        shadowRadius: 2,
      },
      android: { elevation: 1 },
    }),
  },

  // --- 탭 텍스트 ---
  tabText: {
    fontSize: 14,
    fontWeight: "500",
    color: "#8B95A1", // 비활성: 연한 회색
  },
  // [Active] 선택되었을 때 텍스트
  tabTextActive: {
    color: "#191F28", // 활성: 진한 회색/검정
    fontWeight: "700",
  },

  // 레이아웃 균형용 더미
  dummySpace: {
    width: 40, 
  },
});