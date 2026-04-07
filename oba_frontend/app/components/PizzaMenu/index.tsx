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
    sliceOpacity,
    slice1X, slice1Y,
    slice2X, slice2Y,
    slice3X, slice3Y,
    isOpen,
    factor,
    anim,
    baseX, baseY,
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
      {/* Slices - positioned relative to container via absolute positioning */}
      <View
        pointerEvents={isOpen ? "auto" : "none"}
        style={StyleSheet.absoluteFill}
      >
        <PizzaSlice
          source={require("../../../assets/navi/navi_slice_1.png")}
          translateX={slice1X} translateY={slice1Y} scale={sliceScale}
          sliceOpacity={sliceOpacity}
          onPressRoute="/(tabs)/my" isOpen={isOpen} onToggle={toggle}
          factor={factor} anim={anim} label="마이"
          sliceWidth={24} sliceHeight={33}
          labelOffsetX={-20} labelOffsetY={-40}
        />
        <PizzaSlice
          source={require("../../../assets/navi/navi_slice_2.png")}
          translateX={slice2X} translateY={slice2Y} scale={sliceScale}
          sliceOpacity={sliceOpacity}
          onPressRoute="/(tabs)/report" isOpen={isOpen} onToggle={toggle}
          factor={factor} anim={anim} label="리포트"
          sliceWidth={33} sliceHeight={29}
          labelOffsetX={-45} labelOffsetY={-20}
        />
        <PizzaSlice
          source={require("../../../assets/navi/navi_slice_3.png")}
          translateX={slice3X} translateY={slice3Y} scale={sliceScale}
          sliceOpacity={sliceOpacity}
          onPressRoute="/(tabs)/wrongArticles" isOpen={isOpen} onToggle={toggle}
          factor={factor} anim={anim} label="틀린문제"
          sliceWidth={34} sliceHeight={26}
          labelOffsetX={-70} labelOffsetY={0}
        />
      </View>

      {/* Base half pizza - toggle button */}
      <Pressable onPress={toggle} style={StyleSheet.absoluteFill}>
        <Animated.Image
          source={require("../../../assets/navi/navi_half.png")}
          style={{
            width: halfSize, height: halfSize,
            transform: [
              { scale: halfScale },
              { translateX: baseX },
              { translateY: baseY },
            ],
          }}
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
  },
});
