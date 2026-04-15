import type { Config } from 'tailwindcss'

export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        brand: {
          50: '#eff6ff',
          500: '#0f3460',
          600: '#0d2d54',
          700: '#0a2041',
        },
      },
    },
  },
  plugins: [],
} satisfies Config
