import React, { useState, useEffect, useCallback, memo } from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import Header from './Header';
import Footer from './Footer';
import BottomNavigation from './BottomNavigation';
import { useAuth } from '../../context/AuthContext';
import { useSocket } from '../../context/SocketContext';
import CookieConsent from '../common/CookieConsent';

// Memoized Layout component for performance optimization
const Layout = memo(() => {
  const { isAuthenticated } = useAuth();
  const { isConnected, unreadCount } = useSocket();
  const location = useLocation();
  const [isMobile, setIsMobile] = useState(false);

  // Detect mobile viewport for responsive adjustments
  useEffect(() => {
    const checkMobile = () => {
      setIsMobile(window.innerWidth < 768);
    };
    
    checkMobile();
    window.addEventListener('resize', checkMobile);
    return () => window.removeEventListener('resize', checkMobile);
  }, []);

  // Handle keyboard appearance on mobile
  useEffect(() => {
    const handleKeyboardShow = () => {
      document.body.classList.add('keyboard-open');
    };
    
    const handleKeyboardHide = () => {
      document.body.classList.remove('keyboard-open');
    };
    
    // Listen for visual viewport changes (keyboard on mobile)
    if (typeof window.visualViewport !== 'undefined') {
      window.visualViewport.addEventListener('resize', () => {
        const viewport = window.visualViewport;
        if (viewport.height < window.innerHeight * 0.8) {
          handleKeyboardShow();
        } else {
          handleKeyboardHide();
        }
      });
    }
    
    return () => {
      document.body.classList.remove('keyboard-open');
    };
  }, []);

  // Connection status indicator with smooth transitions
  const ConnectionBanner = useCallback(() => {
    if (isConnected) return null;
    
    return (
      <div 
        className="fixed top-16 left-0 right-0 bg-amber-500 text-white text-center py-2 text-sm z-40 transition-transform duration-300"
        role="alert"
        aria-live="polite"
      >
        <div className="flex items-center justify-center space-x-2">
          <svg className="w-4 h-4 animate-pulse" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 5.636a9 9 0 010 12.728m0 0l-2.829-2.829m2.829 2.829L21 21M15.536 8.464a5 5 0 010 7.072m0 0l-2.829-2.829m-4.243 2.829a4.978 4.978 0 01-1.414-2.83m-1.414 5.658a9 9 0 01-2.167-9.238m7.824 2.167a1 1 0 111.414 1.414m-1.414-1.414L3 3m8.293 8.293l1.414 1.414" />
          </svg>
          <span className="font-medium">Reconnecting...</span>
        </div>
      </div>
    );
  }, [isConnected]);

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col">
      {/* Header - Fixed top with safe area support */}
      <Header />
      
      {/* Main Content - Adjusted for fixed header */}
      <main 
        className={`
          flex-1 
          pt-16 
          ${isMobile ? 'pb-16' : 'pb-0'}
          transition-all duration-300
        `}
      >
        <Outlet />
      </main>
      
      {/* Footer - Hidden on mobile and keyboard open */}
      <footer className={`
        hidden md:block 
        bg-white border-t border-gray-200 
        transition-transform duration-300
        ${document.body.classList.contains('keyboard-open') ? 'translate-y-full' : ''}
      `}>
        <Footer />
      </footer>
      
      {/* Bottom Navigation - Mobile only */}
      {isAuthenticated && !document.body.classList.contains('keyboard-open') && (
        <BottomNavigation unreadCount={unreadCount} />
      )}
      
      {/* Connection Status Indicator */}
      <ConnectionBanner />
      
      {/* Cookie Consent */}
      <CookieConsent />
    </div>
  );
});

// Display name for debugging
Layout.displayName = 'Layout';

export default Layout;
