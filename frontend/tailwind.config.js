/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx,ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // Neutral slate enterprise palette
        surface: {
          base: "#090d16",
          elevated: "#0f172a",
          card: "#131d31",
          border: "#1e293b",
          borderMuted: "#334155",
          hover: "#1e293b",
        },
        // Restrained accent: Deep Teal
        accent: {
          DEFAULT: "#0d9488",
          hover: "#14b8a6",
          muted: "rgba(13, 148, 136, 0.15)",
          border: "#0f766e",
        },
        // Semantic WCAG AA severity colors
        sev: {
          critical: "#ef4444",
          criticalBg: "rgba(239, 68, 68, 0.15)",
          criticalBorder: "#dc2626",

          high: "#f97316",
          highBg: "rgba(249, 115, 22, 0.15)",
          highBorder: "#ea580c",

          medium: "#f59e0b",
          mediumBg: "rgba(245, 158, 11, 0.15)",
          mediumBorder: "#d97706",

          low: "#3b82f6",
          lowBg: "rgba(59, 130, 246, 0.15)",
          lowBorder: "#2563eb",

          info: "#64748b",
          infoBg: "rgba(100, 116, 139, 0.15)",
          infoBorder: "#475569",
        },
      },
      fontFamily: {
        sans: ["Inter", "-apple-system", "BlinkMacSystemFont", "Segoe UI", "Roboto", "sans-serif"],
        mono: ["JetBrains Mono", "IBM Plex Mono", "Consolas", "monospace"],
      },
      borderRadius: {
        sm: "3px",
        DEFAULT: "4px",
        md: "6px",
        lg: "8px",
      },
      boxShadow: {
        none: "none",
        subtle: "0 1px 2px 0 rgba(0, 0, 0, 0.25)",
      },
    },
  },
  plugins: [],
};
