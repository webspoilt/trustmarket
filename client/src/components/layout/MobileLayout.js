import React, { useState, useEffect, useCallback, memo } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { ArrowLeftIcon } from '@heroicons/react/24/outline';
import { useAuth } from '../../context/AuthContext';
import { useSocket } from '../../context/SocketContext';

// Memoized MobileLayout for better performance
const MobileLayout = memo(({ 
  children, 
  title, 
  showBack = true, 
  actions = null,
  showBottomNav = true 
}) => {
  const navigate = useNavigate();
  const location = useLocation();
  const { isAuthenticated } = useAuth();
  const { isConnected, unreadCount } = useSocket();
  const [showBottomNavBar, setShowBottomNavBar] = useState(true);

  // Handle keyboard visibility to hide bottom nav
  useEffect(() => {
    if (typeof window.visualViewport !== 'undefined') {
      const handleResize = () => {
        const viewport = window.visualViewport;
        const keyboardOpen = viewport.height < window.innerHeight * 0.7;
        setShowBottomNavBar(!keyboardOpen);
      };
      
      window.visualViewport.addEventListener('resize', handleResize);
      return () => window.visualViewport.removeEventListener('resize', handleResize);
    }
  }, []);

  const handleBack = useCallback(() => {
    if (window.history.length > 1) {
      navigate(-1);
    } else {
      navigate('/');
    }
  }, [navigate]);

  const isCurrentRoute = useCallback((path) => {
    return location.pathname === path;
  }, [location.pathname]);

  // Connection status component
  const ConnectionBanner = useCallback(() => {
    if (isConnected) return null;
    
    return (
      <div className="fixed top-[60px] left-0 right-0 bg-amber-500 text-white text-center py-1.5 text-xs z-40">
        <div className="flex items-center justify-center space-x-1.5">
          <div className="w-1.5 h-1.5 bg-white rounded-full animate-pulse" />
          <span>Reconnecting...</span>
        </div>
      </div>
    );
  }, [isConnected]);

  // Safe area padding for notched devices
  const headerPadding = "safe-area-pt";
  const bottomPadding = "safe-area-pb";

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col">
      {/* Mobile Header */}
      <header 
        className={`
          fixed top-0 left-0 right-0 
          bg-white border-b border-gray-200 
          z-50
          ${headerPadding}
        `}
      >
        <div className="flex items-center justify-between px-4 h-14">
          <div className="flex items-center flex-1 min-w-0">
            {showBack && (
              <button
                onClick={handleBack}
                className="
                  p-2 -ml-2 
                  text-gray-600 hover:text-gray-900 
                  hover:bg-gray-100 rounded-full 
                  transition-colors duration-200
                  touch-manipulation
                  focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2
                "
                aria-label="Go back"
                accessibilityLabel="Go back"
              >
                <ArrowLeftIcon className="w-5 h-5" />
              </button>
            )}
            
            {title && (
              <h1 className="ml-2 text-lg font-semibold text-gray-900 truncate">
                {title}
              </h1>
            )}
          </div>
          
          {actions && (
            <div className="flex items-center space-x-1 ml-2">
              {actions}
            </div>
          )}
        </div>
      </header>
      
      {/* Connection Status */}
      <ConnectionBanner />
      
      {/* Main Content */}
      <main className="flex-1 pt-14">
        {children}
      </main>
      
      {/* Bottom Navigation */}
      {showBottomNav && isAuthenticated && showBottomNavBar && (
        <nav 
          className={`
            fixed bottom-0 left-0 right-0 
            bg-white border-t border-gray-200 
            ${bottomPadding}
            z-50
          `}
          role="navigation"
          aria-label="Main navigation"
        >
          <div className="flex items-center justify-around px-2 py-1">
            {/* Home */}
            <NavButton
              onClick={() => navigate('/')}
              isActive={isCurrentRoute('/')}
              icon={
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
                </svg>
              }
              label="Home"
            />
            
            {/* Search */}
            <NavButton
              onClick={() => navigate('/search')}
              isActive={isCurrentRoute('/search')}
              icon={
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
              }
              label="Search"
            />
            
            {/* Sell Button */}
            <button
              onClick={() => navigate('/create-listing')}
              className="
                relative -top-4 
                w-14 h-14 
                bg-primary-600 rounded-full 
                flex items-center justify-center 
                shadow-lg shadow-primary-600/30
                transition-transform duration-200
                active:scale-95
                focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2
              "
              aria-label="Create new listing"
            >
              <svg className="w-7 h-7 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M12 4v16m8-8H4" />
              </svg>
            </button>
            
            {/* Messages */}
            <NavButton
              onClick={() => navigate('/messages')}
              isActive={location.pathname.startsWith('/messages')}
              icon={
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
                </svg>
              }
              label="Chat"
              badge={unreadCount}
            />
            
            {/* Profile */}
            <NavButton
              onClick={() => navigate('/profile')}
              isActive={location.pathname.startsWith('/profile')}
              icon={
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                </svg>
              }
              label="Profile"
            />
          </div>
        </nav>
      )}
    </div>
  );
});

// Memoized NavButton component for performance
const NavButton = memo(({ onClick, isActive, icon, label, badge }) => (
  <button
    onClick={onClick}
    className={`
      flex flex-col items-center justify-center 
      py-2 px-3 min-w-[64px]
      text-xs font-medium
      transition-colors duration-200
      touch-manipulation
      rounded-lg
      ${isActive 
        ? 'text-primary-600' 
        : 'text-gray-600 hover:text-gray-900'
      }
      focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2
    `}
    aria-current={isActive ? 'page' : undefined}
  >
    <div className="relative">
      {icon}
      {badge > 0 && (
        <span 
          className="
            absolute -top-1 -right-1 
            w-5 h-5 
            bg-error text-white 
            text-xs font-bold rounded-full 
            flex items-center justify-center
            animate-pulse
          "
          aria-label={`${badge} unread messages`}
        >
          {badge > 99 ? '99+' : badge}
        </span>
      )}
    </div>
    <span className="mt-1">{label}</span>
  </button>
));

NavButton.displayName = 'NavButton';

// Display name for debugging
MobileLayout.displayName = 'MobileLayout';

export default MobileLayout;
