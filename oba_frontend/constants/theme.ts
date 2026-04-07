export const COLORS = {
  // Backgrounds (warm cream)
  bgPrimary: "#FFF8F0",
  bgSecondary: "#FFF1E6",
  bgCard: "#FFFFFF",
  bgCardElevated: "#FFFFFF",

  // Primary (warm orange / pizza crust)
  primary: "#FF8C42",
  primaryLight: "#FFA96B",
  primaryDark: "#E67A35",
  primarySurface: "rgba(255, 140, 66, 0.10)",

  // Secondary (golden cheese)
  secondary: "#FFD54F",
  secondaryLight: "#FFE082",
  secondarySurface: "rgba(255, 213, 79, 0.12)",

  // Accent (tomato red)
  accent: "#E74C3C",
  accentLight: "#FF6B6B",
  accentSurface: "rgba(231, 76, 60, 0.08)",

  // Neutrals
  textPrimary: "#2D2016",
  textSecondary: "#6B5B4E",
  textTertiary: "#9E8E7E",
  textPlaceholder: "#C4B5A5",

  border: "rgba(180, 150, 120, 0.2)",
  borderLight: "rgba(180, 150, 120, 0.1)",
  divider: "rgba(180, 150, 120, 0.12)",

  // Semantic
  success: "#27AE60",
  successLight: "#6FCF97",
  successSurface: "rgba(39, 174, 96, 0.08)",
  error: "#E74C3C",
  errorLight: "#FF6B6B",
  errorSurface: "rgba(231, 76, 60, 0.08)",

  // Overlay
  overlay: "rgba(45, 32, 22, 0.6)",
  overlayLight: "rgba(45, 32, 22, 0.2)",

  // Glass effect (warm tint)
  glass: "rgba(180, 150, 120, 0.06)",
  glassBorder: "rgba(180, 150, 120, 0.15)",
};

export const SPACING = {
  xs: 4,
  sm: 8,
  md: 12,
  lg: 16,
  xl: 20,
  xxl: 24,
  xxxl: 32,
};

export const RADIUS = {
  sm: 8,
  md: 12,
  lg: 16,
  xl: 20,
  xxl: 24,
  pill: 100,
  card: 20,
  button: 14,
};

export const TYPO = {
  display: { fontSize: 32, fontWeight: "800" as const, letterSpacing: -0.5 },
  h1: { fontSize: 24, fontWeight: "800" as const, letterSpacing: -0.3 },
  h2: { fontSize: 20, fontWeight: "700" as const, letterSpacing: -0.2 },
  h3: { fontSize: 18, fontWeight: "700" as const },
  body: { fontSize: 16, fontWeight: "400" as const, lineHeight: 26 },
  bodySm: { fontSize: 14, fontWeight: "400" as const, lineHeight: 22 },
  caption: { fontSize: 12, fontWeight: "500" as const },
  label: { fontSize: 14, fontWeight: "600" as const },
  button: { fontSize: 16, fontWeight: "700" as const },
};

export const SHADOWS = {
  sm: {
    shadowColor: "#8B6F47",
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.06,
    shadowRadius: 8,
    elevation: 2,
  },
  md: {
    shadowColor: "#8B6F47",
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.08,
    shadowRadius: 16,
    elevation: 4,
  },
  lg: {
    shadowColor: "#8B6F47",
    shadowOffset: { width: 0, height: 8 },
    shadowOpacity: 0.12,
    shadowRadius: 24,
    elevation: 8,
  },
  glow: {
    shadowColor: "#FF8C42",
    shadowOffset: { width: 0, height: 0 },
    shadowOpacity: 0.25,
    shadowRadius: 20,
    elevation: 10,
  },
};
