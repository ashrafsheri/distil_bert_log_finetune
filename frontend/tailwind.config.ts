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
          // Primary Background (Deep Dark Indigo)
          'dark': '#1a1a2e',
          // Secondary Background (Header/Surface)
          'blue': '#16213e',
          // Primary Accent Blue (Logo, Active Elements)
          'primary': '#7B9EFF',
          // Light Text/Icons
          'light': '#f5f5f5',
          // Muted/Secondary Text
          'muted': '#A0A8C0',
          // Error/Abnormal (Red)
          'error': '#e94560',
          // Success
          'success': '#10B981',
          // Warning
          'warning': '#F59E0B',
        },
        // Light Theme Variants
        'vt-light': {
          'bg': '#ffffff',
          'surface': '#f8fafc',
          'primary': '#3B82F6',
          'text': '#1f2937',
          'muted': '#6b7280',
          'error': '#dc2626',
          'success': '#059669',
          'warning': '#d97706',
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
