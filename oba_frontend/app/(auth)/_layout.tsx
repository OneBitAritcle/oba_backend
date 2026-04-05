import { Stack } from "expo-router";
import AppBackground from "../components/AppBackground"; // 경로 확인 필요

export default function AuthLayout() {
  return (
    <>
      <AppBackground />
      <Stack screenOptions={{ headerShown: false }} />
    </>
  );
}