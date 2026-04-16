/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        brand: {
          50: '#effcf6',
          100: '#d9f8ea',
          500: '#37c978',
          600: '#22b565',
        },
      },
      boxShadow: {
        card: '0 10px 30px rgba(22, 101, 52, 0.08)',
      },
    },
  },
  plugins: [],
}
