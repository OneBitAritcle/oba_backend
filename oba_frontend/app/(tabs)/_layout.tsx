// oba_frontend/app/(tabs)/_layout.tsx
import { Stack } from "expo-router";

export default function TabsLayout() {
  return (
    <Stack screenOptions={{ headerShown: false }}>
      <Stack.Screen name="index" />
      <Stack.Screen name="my/index" />
      <Stack.Screen name="report/index" />
      <Stack.Screen name="wrongArticles/index" />
    </Stack>
  );
}