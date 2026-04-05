import { useRef, useState } from "react";
import { Animated, useWindowDimensions } from "react-native";

export default function usePizzaAnimation() {
  const anim = useRef(new Animated.Value(0)).current;
  const { width, height } = useWindowDimensions();

  // 아이폰 미니 기준 스케일
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

  /* -------------------------------
   * ✅ 닫힌 상태에서 전체 피자(베이스 포함)를 좌상단으로 조금 이동
   * - 원하는 만큼만 바꾸면 됨 (지금은 약 20px)
   * ----------------------------- */
  const CLOSED_SHIFT = { x: -20 * factor, y: -20 * factor };

  // ✅ 열렸을 때 베이스 위치 (닫힌 위치보다 조금 더 왼쪽 위로 이동)
  const OPEN_SHIFT_BASE = { x: -20 * factor, y: -20 * factor };

  // ✅ 베이스(조각 외 나머지 피자) 이동
  const baseX = anim.interpolate({
    inputRange: [0, 1],
    outputRange: [CLOSED_SHIFT.x, OPEN_SHIFT_BASE.x],
  });
  const baseY = anim.interpolate({
    inputRange: [0, 1],
    outputRange: [CLOSED_SHIFT.y, OPEN_SHIFT_BASE.y],
  });

  /* -------------------------------
   * 닫힌 상태: (조각 좌표는 그대로 두거나)
   * - 조각도 같이 이동시키고 싶으면 CLOSED에도 CLOSED_SHIFT를 더해도 됨
   * ----------------------------- */
  const CLOSED = {
    slice1: { x: -27.5 * factor, y: -37.1 * factor },
    slice2: { x: -38.4 * factor, y: -34.8 * factor },
    slice3: { x: -39.2 * factor, y: -15.2 * factor },
  };

  const OPEN = {
    slice1: { x: -76.4 * factor, y: -109.0 * factor },
    slice2: { x: -120.3 * factor, y: -89.0 * factor },
    slice3: { x: -125.6 * factor, y: -33.7 * factor },
  };

  const slice1X = anim.interpolate({ inputRange: [0, 1], outputRange: [CLOSED.slice1.x, OPEN.slice1.x] });
  const slice1Y = anim.interpolate({ inputRange: [0, 1], outputRange: [CLOSED.slice1.y, OPEN.slice1.y] });

  const slice2X = anim.interpolate({ inputRange: [0, 1], outputRange: [CLOSED.slice2.x, OPEN.slice2.x] });
  const slice2Y = anim.interpolate({ inputRange: [0, 1], outputRange: [CLOSED.slice2.y, OPEN.slice2.y] });

  const slice3X = anim.interpolate({ inputRange: [0, 1], outputRange: [CLOSED.slice3.x, OPEN.slice3.x] });
  const slice3Y = anim.interpolate({ inputRange: [0, 1], outputRange: [CLOSED.slice3.y, OPEN.slice3.y] });

  const halfScale = anim.interpolate({ inputRange: [0, 1], outputRange: [1, 1.8] });

  const sliceScale = anim.interpolate({
    inputRange: [0, 1.7, 1.8],
    outputRange: [0.6, 1.8, 1.7],
  });

  return {
    toggle,
    isOpen,
    factor,
    anim,

    // ✅ 추가로 내보내기 (베이스용)
    baseX,
    baseY,

    halfScale,
    sliceScale,
    slice1X,
    slice1Y,
    slice2X,
    slice2Y,
    slice3X,
    slice3Y,
  };
}
