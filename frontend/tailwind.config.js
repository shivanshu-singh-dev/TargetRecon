/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        graphite: {
          950: '#0b0f17',
          900: '#111827',
          800: '#1e293b',
          700: '#334155',
          600: '#475569',
        },
        navy: {
          950: '#081020',
          900: '#0d1b2a',
          800: '#1b263b',
          700: '#2b3b55',
        },
        cyber: {
          teal: '#06b6d4',
          cyan: '#22d3ee',
          green: '#10b981',
          amber: '#f59e0b',
          rose: '#f43f5e',
          indigo: '#6366f1',
        }
      },
    },
  },
  plugins: [],
}
