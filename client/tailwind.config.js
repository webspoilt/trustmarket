/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
    "./public/index.html",
  ],
  theme: {
    extend: {
      colors: {
        // TrustMarket Brand Colors
        primary: {
          50: '#eff6ff',
          100: '#dbeafe',
          200: '#bfdbfe',
          300: '#93c5fd',
          400: '#60a5fa',
          500: '#3b82f6', // Main brand color
          600: '#2563eb',
          700: '#1d4ed8',
          800: '#1e40af',
          900: '#1e3a8a',
        },
        success: '#10b981',
        warning: '#f59e0b',
        error: '#ef4444',
        elite: '#854d0e',
        
        // Neutral Colors
        neutral: {
          0: '#ffffff',
          50: '#f8fafc',
          100: '#f1f5f9',
          200: '#e2e8f0',
          300: '#cbd5e1',
          400: '#94a3b8',
          500: '#64748b',
          600: '#475569',
          700: '#334155',
          800: '#1e293b',
          900: '#0f172a',
        },
        
        // Trust Score Colors
        trust: {
          newbie: '#6b7280',
          resident: '#3b82f6',
          veteran: '#10b981',
          elite: '#f59e0b',
        },
        
        // Semantic Colors
        safe: '#10b981',
        caution: '#f59e0b',
        risk: '#ef4444',
      },
      
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'Monaco', 'Cascadia Code', 'Segoe UI Mono', 'Roboto Mono', 'Oxygen Mono', 'Ubuntu Monospace', 'Source Code Pro', 'Fira Mono', 'Droid Sans Mono', 'Courier New', 'monospace'],
      },
      
      fontSize: {
        'xs': ['0.75rem', { lineHeight: '1rem' }],
        'sm': ['0.875rem', { lineHeight: '1.25rem' }],
        'base': ['1rem', { lineHeight: '1.5rem' }],
        'lg': ['1.125rem', { lineHeight: '1.75rem' }],
        'xl': ['1.25rem', { lineHeight: '1.75rem' }],
        '2xl': ['1.5rem', { lineHeight: '2rem' }],
        '3xl': ['1.875rem', { lineHeight: '2.25rem' }],
        '4xl': ['2.25rem', { lineHeight: '2.5rem' }],
        '5xl': ['3rem', { lineHeight: '1' }],
        '6xl': ['3.75rem', { lineHeight: '1' }],
      },
      
      spacing: {
        '18': '4.5rem',
        '88': '22rem',
        '128': '32rem',
      },
      
      maxWidth: {
        '8xl': '88rem',
        '9xl': '96rem',
      },
      
      minHeight: {
        'touch': '44px',
        'screen-safe': '100vh',
      },
      
      minWidth: {
        'touch': '44px',
      },
      
      borderRadius: {
        'sm': '4px',    // Buttons, Inputs, Tags
        'md': '8px',    // Cards, Video Containers
        'lg': '12px',   // Modals, Bottom Sheets
      },
      
      boxShadow: {
        'sm': '0 1px 2px 0 rgb(0 0 0 / 0.05)',
        'DEFAULT': '0 1px 3px 0 rgb(0 0 0 / 0.1), 0 1px 2px -1px rgb(0 0 0 / 0.1)',
        'md': '0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1)',
        'lg': '0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1)',
        'xl': '0 20px 25px -5px rgb(0 0 0 / 0.1), 0 8px 10px -6px rgb(0 0 0 / 0.1)',
        '2xl': '0 25px 50px -12px rgb(0 0 0 / 0.25)',
        'inner': 'inset 0 2px 4px 0 rgb(0 0 0 / 0.05)',
        'trust': '0 4px 12px rgba(59, 130, 246, 0.4)',
      },
      
      animation: {
        'fade-in': 'fadeIn 0.3s ease-in-out',
        'slide-up': 'slideUp 0.3s ease-out',
        'slide-down': 'slideDown 0.3s ease-out',
        'scale-in': 'scaleIn 0.2s ease-out',
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'bounce-slow': 'bounce 2s infinite',
      },
      
      backdropBlur: {
        'xs': '2px',
      },
      
      transitionProperty: {
        'height': 'height',
        'spacing': 'margin, padding',
      },
      
      screens: {
        'xs': '475px',
        '3xl': '1600px',
      },
      
      zIndex: {
        '60': '60',
        '70': '70',
        '80': '80',
        '90': '90',
        '100': '100',
      },
      
      // Custom utilities for TrustMarket
      aspectRatio: {
        'video': '4 / 5',
        'listing': '4 / 5',
        'thumbnail': '1 / 1',
      },
      
      // Custom gradients
      backgroundImage: {
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
        'gradient-conic': 'conic-gradient(from 180deg at 50% 50%, var(--tw-gradient-stops))',
        'trust-gradient': 'linear-gradient(135deg, #eff6ff 0%, #ffffff 100%)',
      },
      
      // Safe area utilities for mobile PWA
      padding: {
        'safe-top': 'env(safe-area-inset-top)',
        'safe-bottom': 'env(safe-area-inset-bottom)',
        'safe-left': 'env(safe-area-inset-left)',
        'safe-right': 'env(safe-area-inset-right)',
      },
      
      // Custom border widths
      borderWidth: {
        '3': '3px',
        '5': '5px',
      },
      
      // Custom container
      container: {
        center: true,
        padding: {
          DEFAULT: '1rem',
          sm: '2rem',
          lg: '4rem',
          xl: '5rem',
          '2xl': '6rem',
        },
      },
    },
  },
  plugins: [
    require('@tailwindcss/forms'),
    require('@tailwindcss/typography'),
    require('@tailwindcss/aspect-ratio'),
    
    // Custom plugin for TrustMarket components
    function({ addUtilities, theme }) {
      const newUtilities = {
        // Trust score utilities
        '.trust-score-high': {
          color: theme('colors.success'),
        },
        '.trust-score-medium': {
          color: theme('colors.warning'),
        },
        '.trust-score-low': {
          color: theme('colors.error'),
        },
        
        // Safety utilities
        '.safety-safe': {
          backgroundColor: theme('colors.green.50'),
          borderColor: theme('colors.green.200'),
          color: theme('colors.green.800'),
        },
        '.safety-caution': {
          backgroundColor: theme('colors.yellow.50'),
          borderColor: theme('colors.yellow.200'),
          color: theme('colors.yellow.800'),
        },
        '.safety-risk': {
          backgroundColor: theme('colors.red.50'),
          borderColor: theme('colors.red.200'),
          color: theme('colors.red.800'),
        },
        
        // Video overlay utilities
        '.video-overlay-play': {
          '&::before': {
            content: '""',
            position: 'absolute',
            top: '50%',
            left: '50%',
            transform: 'translate(-50%, -50%)',
            width: '48px',
            height: '48px',
            backgroundColor: 'rgba(0, 0, 0, 0.7)',
            borderRadius: '50%',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          },
          '&::after': {
            content: '""',
            position: 'absolute',
            top: '50%',
            left: '50%',
            transform: 'translate(-40%, -50%)',
            borderLeft: '16px solid white',
            borderTop: '10px solid transparent',
            borderBottom: '10px solid transparent',
          },
        },
        
        // Touch-friendly utilities
        '.touch-manipulation': {
          'touch-action': 'manipulation',
        },
        
        // Selection utilities
        '.select-none': {
          'user-select': 'none',
        },
        '.select-text': {
          'user-select': 'text',
        },
        
        // Scrollbar utilities
        '.scrollbar-hide': {
          '-ms-overflow-style': 'none',
          'scrollbar-width': 'none',
          '&::-webkit-scrollbar': {
            display: 'none',
          },
        },
        
        // Glass morphism utilities
        '.glass': {
          'backdrop-filter': 'blur(10px)',
          '-webkit-backdrop-filter': 'blur(10px)',
          'background': 'rgba(255, 255, 255, 0.8)',
        },
        '.glass-dark': {
          'backdrop-filter': 'blur(10px)',
          '-webkit-backdrop-filter': 'blur(10px)',
          'background': 'rgba(0, 0, 0, 0.8)',
        },
      };
      
      addUtilities(newUtilities);
    },
  ],
  // Dark mode configuration (for future implementation)
  darkMode: 'class',
  
  // Future configuration
  future: {
    hoverOnlyWhenSupported: true,
  },
};