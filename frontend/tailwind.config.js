/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        background: "#0B1120",
        surface: {
          DEFAULT: "#111827",
          subtle: "#0F172A",
          elevated: "#162032",
          hover: "#1E293B",
        },
        border: {
          DEFAULT: "#263244",
          subtle: "#1E293B",
          highlight: "#334155",
        },
        cyan: {
          DEFAULT: "#06B6D4",
          light: "#22D3EE",
          dark: "#0891B2",
          glow: "rgba(6, 182, 212, 0.15)",
        },
        primary: {
          DEFAULT: "#06B6D4",
          foreground: "#041C24",
          50: "#ECFEFF",
          100: "#CFFAFE",
          200: "#A5F3FC",
          300: "#67E8F9",
          400: "#22D3EE",
          500: "#06B6D4",
          600: "#0891B2",
          700: "#0E7490",
          800: "#155E75",
          900: "#164E63",
        },
        accent: {
          blue: "#3B82F6",
          purple: "#8B5CF6",
        },
        status: {
          danger: "#EF4444",
          warning: "#F59E0B",
          success: "#10B981",
          info: "#3B82F6",
        },
      },
      fontFamily: {
        sans: ["Inter", "-apple-system", "BlinkMacSystemFont", "Segoe UI", "Roboto", "sans-serif"],
        mono: ["JetBrains Mono", "Fira Code", "monospace"],
      },
      animation: {
        "pulse-slow": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "scan-line": "scanline 2.5s ease-in-out infinite",
      },
      keyframes: {
        scanline: {
          "0%, 100%": { transform: "translateY(0%)", opacity: "0.2" },
          "50%": { transform: "translateY(100%)", opacity: "0.8" },
        },
      },
    },
  },
  plugins: [],
};

