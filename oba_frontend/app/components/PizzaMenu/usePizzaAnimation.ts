import { useRef, useState } from "react";
import { Animated, useWindowDimensions } from "react-native";

export default function usePizzaAnimation() {
  const anim = useRef(new Animated.Value(0)).current;
  const { width, height } = useWindowDimensions();
  const factor = Math.min(width, height) / 390;
  const [isOpen, setIsOpen] = useState(false);

  const toggle = () => {
    const next = !isOpen;
    setIsOpen(next);
    Animated.spring(anim, {
      toValue: next ? 1 : 0,
      friction: 6,
      tension: 60,
      useNativeDriver: true,
    }).start();
  };

  // ═══ GEOMETRY (all in base units × factor) ═══
  //
  // Container: 70×70.
  // Slice wrapper: absoluteFill → same as container (0,0)-(70,70).
  // sliceContainer: position:absolute at (0,0) of wrapper = container (0,0).
  // After translate(tx,ty): slice top-left at (tx, ty).
  //
  // Half-pizza: 581×628 original, contain in 70×70 → renders 64.76×70.
  //   Content offset in box: ((70-64.76)/2, 0) = (2.62, 0).
  //   Transform translateX=-5 shifts image box left.
  //   Content top-left: (-5 + 2.62, 0) = (-2.38, 0).
  //   Pizza center (555/581, 335/628) → rendered (61.86, 37.34) from content top-left.
  //   Pizza center in container: (-2.38 + 61.86, 37.34) = (59.48, 37.34).
  //
  // Slice tip = (tx + tipX, ty + tipY) must equal pizza center.
  //   tx = 59.48 - tipX,  ty = 37.34 - tipY
  //
  // Revised pizza center: ~(340, 360) in 581×628 original
  //   → rendered (37.9, 40.1) in 64.76×70 image
  //   → container coords: (-5 + 2.62 + 37.9, 40.1) = (35.52, 40.13)
  //
  // Slice 1 (24×33): tip at (15/235, 316/326) → (1.53, 31.98) → tx=34.0, ty=8.1
  // Slice 2 (33×29): tip at (160/324, 275/283) → (16.30, 28.18) → tx=19.2, ty=12.0
  // Slice 3 (34×26): tip at (310/330, 248/257) → (31.94, 25.09) → tx=3.6, ty=15.0

  const HALF_TX = -5 * factor;
  const baseX = anim.interpolate({ inputRange: [0, 1], outputRange: [HALF_TX, HALF_TX] });
  const baseY = anim.interpolate({ inputRange: [0, 1], outputRange: [0, 0] });

  const CLOSED = {
    slice1: { x: 34.0 * factor, y: 8.1 * factor },
    slice2: { x: 19.2 * factor, y: 12.0 * factor },
    slice3: { x: 3.6 * factor,  y: 15.0 * factor },
  };

  const OPEN = {
    slice1: { x: CLOSED.slice1.x - 65 * factor, y: CLOSED.slice1.y - 80 * factor },
    slice2: { x: CLOSED.slice2.x - 95 * factor, y: CLOSED.slice2.y - 55 * factor },
    slice3: { x: CLOSED.slice3.x - 90 * factor, y: CLOSED.slice3.y - 15 * factor },
  };

  const slice1X = anim.interpolate({ inputRange: [0, 1], outputRange: [CLOSED.slice1.x, OPEN.slice1.x] });
  const slice1Y = anim.interpolate({ inputRange: [0, 1], outputRange: [CLOSED.slice1.y, OPEN.slice1.y] });
  const slice2X = anim.interpolate({ inputRange: [0, 1], outputRange: [CLOSED.slice2.x, OPEN.slice2.x] });
  const slice2Y = anim.interpolate({ inputRange: [0, 1], outputRange: [CLOSED.slice2.y, OPEN.slice2.y] });
  const slice3X = anim.interpolate({ inputRange: [0, 1], outputRange: [CLOSED.slice3.x, OPEN.slice3.x] });
  const slice3Y = anim.interpolate({ inputRange: [0, 1], outputRange: [CLOSED.slice3.y, OPEN.slice3.y] });

  const halfScale = anim.interpolate({ inputRange: [0, 1], outputRange: [1, 1.6] });
  const sliceScale = anim.interpolate({ inputRange: [0, 0.5, 1], outputRange: [1, 1.6, 1.5] });
  const sliceOpacity = anim.interpolate({ inputRange: [0, 1], outputRange: [1, 1] });

  return {
    toggle, isOpen, factor, anim,
    baseX, baseY, halfScale,
    sliceScale, sliceOpacity,
    slice1X, slice1Y,
    slice2X, slice2Y,
    slice3X, slice3Y,
  };
}
