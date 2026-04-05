// app/components/PizzaMenu/index.tsx
import { View, Pressable, Animated, StyleSheet } from "react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import usePizzaAnimation from "./usePizzaAnimation";
import PizzaSlice from "./PizzaSlice";

export default function PizzaMenu() {
  const {
    toggle,
    halfScale,
    sliceScale,
    slice1X,
    slice1Y,
    slice2X,
    slice2Y,
    slice3X,
    slice3Y,
    isOpen,
    factor,
    anim,
    baseX,
    baseY,
  } = usePizzaAnimation();

  const insets = useSafeAreaInsets();
  const containerSize = 70 * factor;
  const halfSize = 70 * factor;

  return (
    <View
      style={[
        styles.container,
        { width: containerSize, height: containerSize, bottom: insets.bottom + 16 },
      ]}
    >
      {/* 슬라이스 1: 마이 */}
      <PizzaSlice
        source={require("../../../assets/navi/navi_slice_1.png")}
        translateX={slice1X}
        translateY={slice1Y}
        scale={sliceScale}
        onPressRoute="/(tabs)/my"
        isOpen={isOpen}
        onToggle={toggle}
        factor={factor}
        anim={anim}
        label="마이"
        sliceTouchScale={0.5}
        sliceSize={60}
        labelOffsetX={-25}
        labelOffsetY={-50}
      />

      {/* 슬라이스 2: 리포트 */}
      <PizzaSlice
        source={require("../../../assets/navi/navi_slice_2.png")}
        translateX={slice2X}
        translateY={slice2Y}
        scale={sliceScale}
        onPressRoute="/(tabs)/report"
        isOpen={isOpen}
        onToggle={toggle}
        factor={factor}
        anim={anim}
        label="리포트"
        sliceTouchScale={0.5}
        sliceSize={62.5}
        sliceRotation={0.3}
        labelOffsetX={-55}
        labelOffsetY={-25}
      />

      {/* 슬라이스 3: 틀린문제 */}
      <PizzaSlice
        source={require("../../../assets/navi/navi_slice_3.png")}
        translateX={slice3X}
        translateY={slice3Y}
        scale={sliceScale}
        onPressRoute="/(tabs)/wrongArticles"
        isOpen={isOpen}
        onToggle={toggle}
        factor={factor}
        anim={anim}
        label="틀린문제"
        sliceTouchScale={0.5}
        sliceSize={63}
        sliceRotation={0.5}
        labelOffsetX={-85}
        labelOffsetY={0}
      />

      {/* 기본 피자 반쪽 - 토글 버튼 */}
      <Pressable onPress={toggle}>
        <Animated.Image
          source={require("../../../assets/navi/navi_half.png")}
          style={[
            styles.halfPizza,
            {
              width: halfSize,
              height: halfSize,
              transform: [
                { scale: halfScale },
                { translateX: baseX },
                { translateY: baseY },
              ],
            },
          ]}
          resizeMode="contain"
        />
      </Pressable>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    position: "absolute",

    right: 10,
    width: 50,
    height: 50,
    justifyContent: "center",
    alignItems: "center",
  },
  halfPizza: {
    width: 50,
    height: 50,
  },
});
