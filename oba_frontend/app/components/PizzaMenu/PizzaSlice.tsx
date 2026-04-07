// app/components/PizzaMenu/PizzaSlice.tsx
import React from "react";
import {
  Animated,
  Pressable,
  StyleSheet,
  View,
  ImageSourcePropType,
  Text,
  Image,
} from "react-native";
import { useRouter } from "expo-router";

type Props = {
  source: ImageSourcePropType;
  translateX: Animated.AnimatedInterpolation<number>;
  translateY: Animated.AnimatedInterpolation<number>;
  scale: Animated.AnimatedInterpolation<number>;
  onPressRoute: string;
  isOpen: boolean;
  onToggle: () => void;
  factor: number;
  anim?: Animated.Value;
  label?: string;
  labelOffsetX?: number;
  labelOffsetY?: number;
  labelIconSource?: ImageSourcePropType;
  sliceWidth: number;
  sliceHeight: number;
  sliceOpacity?: Animated.AnimatedInterpolation<number>;
};

export default function PizzaSlice({
  source,
  translateX,
  translateY,
  scale,
  onPressRoute,
  isOpen,
  onToggle,
  factor,
  anim,
  label,
  labelOffsetX,
  labelOffsetY,
  labelIconSource,
  sliceWidth,
  sliceHeight,
  sliceOpacity,
}: Props) {
  const router = useRouter();

  const labelOpacity = anim
    ? anim.interpolate({ inputRange: [0, 0.6, 1], outputRange: [0, 0, 1] })
    : 0;

  const baseSlideX = anim
    ? anim.interpolate({ inputRange: [0, 1], outputRange: [10 * factor, 0] })
    : 0;

  const labelScale = anim
    ? anim.interpolate({ inputRange: [0, 1], outputRange: [0.9, 1] })
    : 1;

  const w = sliceWidth * factor;
  const h = sliceHeight * factor;

  const finalOffsetX = (labelOffsetX ?? 0) * factor;
  const finalOffsetY = (labelOffsetY ?? 0) * factor;

  const translateXWithOffset = anim
    ? Animated.add(baseSlideX, new Animated.Value(finalOffsetX))
    : new Animated.Value(finalOffsetX);
  const translateYWithOffset = new Animated.Value(finalOffsetY);

  const handlePress = () => {
    if (!isOpen) {
      onToggle();
      return;
    }
    try {
      router.push(onPressRoute as any);
    } catch (e) {
      console.warn("Navigation error:", e);
    }
    onToggle();
  };

  return (
    <Animated.View
      style={[
        styles.sliceContainer,
        {
          opacity: sliceOpacity ?? 1,
          transform: [{ translateX }, { translateY }],
        },
      ]}
      pointerEvents="box-none"
    >
      <Pressable onPress={handlePress} hitSlop={0}
        style={{ width: w, height: h, justifyContent: "center", alignItems: "center" }}
      >
        <Animated.Image
          source={source}
          style={{ width: w, height: h, transform: [{ scale }] }}
          resizeMode="contain"
          pointerEvents="none"
        />

        {label && (
          <Animated.View
            style={[
              styles.labelWrapper,
              {
                opacity: labelOpacity,
                transform: [
                  { translateX: translateXWithOffset },
                  { translateY: translateYWithOffset },
                  { scale: labelScale },
                ],
              },
            ]}
          >
            <View style={[styles.labelBubble, {
              borderRadius: 4 * factor,
              paddingHorizontal: 6 * factor,
              paddingVertical: 2 * factor,
            }]}>
              <View style={styles.labelInner}>
                {labelIconSource && (
                  <Image source={labelIconSource}
                    style={{ width: 10 * factor, height: 10 * factor, marginRight: 4 * factor }}
                  />
                )}
                <Text style={[styles.labelText, { fontSize: 13 * factor }]} numberOfLines={1}>
                  {label}
                </Text>
              </View>
            </View>
          </Animated.View>
        )}
      </Pressable>
    </Animated.View>
  );
}

const styles = StyleSheet.create({
  sliceContainer: { position: "absolute" },
  labelWrapper: { position: "absolute" },
  labelBubble: {
    backgroundColor: "rgba(255, 255, 255, 0.95)",
    shadowColor: "#8B6F47",
    shadowOpacity: 0.15,
    shadowOffset: { width: 0, height: 2 },
    shadowRadius: 8,
    elevation: 4,
    overflow: "hidden",
    borderWidth: 1,
    borderColor: "rgba(255, 140, 66, 0.25)",
  },
  labelInner: { flexDirection: "row", alignItems: "center" },
  labelText: { color: "#2D2016", fontWeight: "700" },
});
