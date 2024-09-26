/** @type {import('tailwindcss').Config} */
module.exports = {
  content: {
    relative: true,
    files: ["*.html", "./src/**/*.rs"],
  },
  theme: {
    extend: {
      colors: {
        "brown-3": "#A27B4C",
        "brown-2": "#6C4636",
        "brown-1": "#282527",
        "brown-4": "#BFB28F",
        "brown-5": "#E0D8C8"
      }
    },
  },
  plugins: [],
}

