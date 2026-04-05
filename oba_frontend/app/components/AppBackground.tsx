
// oba_fronted/app/article/components/AppBackground.tsx

import { View, Image, StyleSheet, useWindowDimensions } from "react-native";

export default function AppBackground() {
  const { width, height } = useWindowDimensions();

  // 화면 크기에 따라 이미지 위치를 상대적으로 조정
  const getPosition = (top?: number, left?: number, right?: number, bottom?: number) => {
    return {
      top: top ? (top / 844) * height : undefined, // iPhone 12 Pro 기준 높이 844px
      left: left ? (left / 390) * width : undefined, // iPhone 12 Pro 기준 너비 390px
      right: right ? (right / 390) * width : undefined,
      bottom: bottom ? (bottom / 844) * height : undefined,
    };
  };

  return (
    <View
      style={[
        StyleSheet.absoluteFill,
        { position: "absolute", backgroundColor: "#F5FAFF" }
      ]}
      pointerEvents="none"
    >
      <Image
        source={require("../../assets/pizza/pep.png")}
        style={[styles.decoration, getPosition(100, 140)]}
      />

      <Image
        source={require("../../assets/food/burger.png")}
        style={[styles.decoration, getPosition(180, undefined, 90), { transform: [{ rotate: "-12deg" }] }]}
      />

      <Image
        source={require("../../assets/food/potato.png")}
        style={[styles.decoration, getPosition(330, 60), { transform: [{ rotate: "-12deg" }] }]}
      />

      <Image
        source={require("../../assets/pizza/mar.png")}
        style={[styles.decoration, getPosition(460, undefined, 60), { transform: [{ rotate: "12deg" }] }]}
      />

      <Image
        source={require("../../assets/food/ckin.png")}
        style={[styles.decoration, getPosition(620, 180), { transform: [{ rotate: "16deg" }] }]}
      />

      <Image
        source={require("../../assets/food/chic.png")}
        style={[styles.decoration, getPosition(720, undefined, 50)]}
      />

      <Image
        source={require("../../assets/pizza/hwaa.png")}
        style={[styles.decoration, getPosition(undefined, 100, undefined, 150)]}
      />
    </View>
  );
}



const styles = StyleSheet.create({
  decoration: {
    position: "absolute",
    width: 60,
    height: 60,
    opacity: 0.15,
  },
});
