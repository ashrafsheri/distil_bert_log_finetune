import type { Config } from 'tailwindcss'

const config: Config = {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        'sans': ['Inter', 'Poppins', 'system-ui', 'sans-serif'],
      },
      colors: {
        // VirusTotal Dark Theme Palette
        'vt': {
          // Primary Background (Deep navy)
          'dark': '#0B1220',
          // Secondary Surface
          'blue': '#121C32',
          // Elevated Surface
          'surface': '#19253F',
          // Primary Accent Blue
          'primary': '#4F8DF9',
          // Secondary Accent
          'accent': '#8B5CF6',
          // Light Text/Icons
          'light': '#E8F1FF',
          // Muted/Secondary Text
          'muted': '#98A4C4',
          // Error/Abnormal
          'error': '#F87171',
          // Success
          'success': '#22D3A6',
          // Warning
          'warning': '#F4C15D',
        },
        // Light Theme Variants
        'vt-light': {
          'bg': '#F8FAFF',
          'surface': '#EEF2FF',
          'primary': '#3B82F6',
          'text': '#1F2937',
          'muted': '#6B7280',
          'error': '#EF4444',
          'success': '#10B981',
          'warning': '#F59E0B',
        }
      },
      spacing: {
        '18': '4.5rem',
        '88': '22rem',
      },
      borderRadius: {
        'xl': '0.75rem',
        '2xl': '1rem',
      },
      boxShadow: {
        'vt': '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
        'vt-lg': '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)',
      },
      animation: {
        'fade-in': 'fadeIn 0.5s ease-in-out',
        'slide-up': 'slideUp 0.3s ease-out',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%': { transform: 'translateY(10px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
      },
    },
  },
  plugins: [],
}

export default config
