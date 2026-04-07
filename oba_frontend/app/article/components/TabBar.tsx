import { SafeAreaView } from "react-native-safe-area-context";
import { View, Text, TouchableOpacity, StyleSheet } from "react-native";
import { COLORS, RADIUS, SHADOWS, TYPO, SPACING } from "../../../constants/theme";

export default function TabBar({ activeTab, setActiveTab, goHome }) {
  const tabs = ["기사", "키워드", "퀴즈"];

  return (
    <View style={styles.container}>
      <SafeAreaView edges={["top"]} style={styles.safeArea}>
        <View style={styles.innerContainer}>
          <TouchableOpacity onPress={goHome} style={styles.backBtn} activeOpacity={0.6}>
            <Text style={styles.backText}>←</Text>
          </TouchableOpacity>

          <View style={styles.tabGroup}>
            {tabs.map((tab) => {
              const isActive = activeTab === tab;
              return (
                <TouchableOpacity key={tab} onPress={() => setActiveTab(tab)} style={[styles.tabBtn, isActive && styles.tabBtnActive]} activeOpacity={0.8}>
                  <Text style={[styles.tabText, isActive && styles.tabTextActive]}>{tab}</Text>
                </TouchableOpacity>
              );
            })}
          </View>

          <View style={styles.dummySpace} />
        </View>
      </SafeAreaView>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { zIndex: 10, backgroundColor: COLORS.bgPrimary, borderBottomWidth: 1, borderColor: COLORS.border },
  safeArea: { backgroundColor: "transparent" },
  innerContainer: { height: 54, flexDirection: "row", alignItems: "center", justifyContent: "space-between", paddingHorizontal: SPACING.lg },
  backBtn: { width: 40, height: 40, justifyContent: "center", alignItems: "flex-start" },
  backText: { fontSize: 26, fontWeight: "400", color: COLORS.textPrimary, marginTop: -4 },
  tabGroup: {
    flexDirection: "row", gap: 4,
    backgroundColor: COLORS.bgSecondary, padding: 4, borderRadius: 25,
    borderWidth: 1, borderColor: COLORS.border,
  },
  tabBtn: { paddingVertical: 6, paddingHorizontal: 14, borderRadius: 20 },
  tabBtnActive: { backgroundColor: COLORS.primary, ...SHADOWS.sm },
  tabText: { ...TYPO.label, color: COLORS.textTertiary },
  tabTextActive: { color: "#FFFFFF", fontWeight: "700" },
  dummySpace: { width: 40 },
});
