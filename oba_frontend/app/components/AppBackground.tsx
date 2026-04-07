import { View, StyleSheet } from "react-native";
import { COLORS } from "../../constants/theme";

export default function AppBackground() {
  return (
    <View style={[StyleSheet.absoluteFill, styles.container]} pointerEvents="none">
      <View style={styles.glowTopRight} />
      <View style={styles.glowBottomLeft} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    position: "absolute",
    backgroundColor: COLORS.bgPrimary,
  },
  glowTopRight: {
    position: "absolute",
    top: -150,
    right: -100,
    width: 300,
    height: 300,
    borderRadius: 150,
    backgroundColor: COLORS.secondary,
    opacity: 0.08,
  },
  glowBottomLeft: {
    position: "absolute",
    bottom: -80,
    left: -120,
    width: 250,
    height: 250,
    borderRadius: 125,
    backgroundColor: COLORS.primary,
    opacity: 0.05,
  },
});
