import React, { useState, useRef, useEffect, useCallback, memo } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { useSocket } from '../../context/SocketContext';
import { useNotification } from '../../context/NotificationContext';
import {
  Bars3Icon,
  XMarkIcon,
  BellIcon,
  MagnifyingGlassIcon,
  UserIcon,
  Cog6ToothIcon,
  ArrowRightOnRectangleIcon,
  PlusIcon,
} from '@heroicons/react/24/outline';

// Memoized Header component for performance optimization
const Header = memo(() => {
  const navigate = useNavigate();
  const location = useLocation();
  const { user, isAuthenticated, logout } = useAuth();
  const { unreadCount } = useSocket();
  const { permission: notificationPermission } = useNotification();
  
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [isProfileMenuOpen, setIsProfileMenuOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [isMobile, setIsMobile] = useState(false);
  const [atTop, setAtTop] = useState(true);

  const profileMenuRef = useRef(null);
  const menuRef = useRef(null);

  // Detect mobile viewport
  useEffect(() => {
    const checkMobile = () => {
      setIsMobile(window.innerWidth < 768);
    };
    checkMobile();
    window.addEventListener('resize', checkMobile);
    return () => window.removeEventListener('resize', checkMobile);
  }, []);

  // Handle scroll effects
  useEffect(() => {
    const handleScroll = () => {
      setAtTop(window.scrollY <= 10);
    };
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  // Close profile menu when clicking outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (profileMenuRef.current && !profileMenuRef.current.contains(event.target)) {
        setIsProfileMenuOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Handle escape key
  useEffect(() => {
    const handleKeyDown = (event) => {
      if (event.key === 'Escape') {
        setIsMenuOpen(false);
        setIsProfileMenuOpen(false);
      }
    };
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, []);

  const handleSearch = useCallback((e) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      navigate(`/search?q=${encodeURIComponent(searchQuery.trim())}`);
      setSearchQuery('');
      setIsMenuOpen(false);
    }
  }, [searchQuery, navigate]);

  const handleLogout = useCallback(async () => {
    try {
      await logout();
      navigate('/');
    } catch (error) {
      console.error('Logout error:', error);
    }
    setIsProfileMenuOpen(false);
    setIsMenuOpen(false);
  }, [logout, navigate]);

  const isActive = useCallback((path) => {
    if (path === '/' && location.pathname === '/') return true;
    if (path !== '/' && location.pathname.startsWith(path)) return true;
    return false;
  }, [location.pathname]);

  const toggleMenu = useCallback(() => {
    setIsMenuOpen(prev => !prev);
    if (isProfileMenuOpen) setIsProfileMenuOpen(false);
  }, [isProfileMenuOpen]);

  return (
    <header 
      className={`
        fixed top-0 left-0 right-0 
        bg-white/95 backdrop-blur-sm
        border-b border-gray-200 
        z-50
        transition-all duration-300
        ${atTop ? '' : 'shadow-md'}
      `}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <div className="flex items-center flex-shrink-0">
            <Link 
              to="/" 
              className="flex items-center space-x-2"
              aria-label="TrustMarket Home"
            >
              <div className="w-8 h-8 bg-primary-600 rounded-lg flex items-center justify-center">
                <svg className="w-5 h-5 text-white" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M3 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1z" clipRule="evenodd" />
                </svg>
              </div>
              <span className="text-xl font-bold text-gray-900 hidden sm:block">TrustMarket</span>
            </Link>
          </div>

          {/* Desktop Search Bar */}
          <div className="hidden md:flex flex-1 max-w-xl mx-8">
            <form onSubmit={handleSearch} className="w-full relative">
              <label htmlFor="search" className="sr-only">Search</label>
              <input
                id="search"
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search for cars, mobiles, furniture..."
                className="
                  w-full pl-10 pr-4 py-2 
                  border border-gray-300 rounded-lg
                  focus:ring-2 focus:ring-primary-500 focus:border-primary-500
                  transition-all duration-200
                  text-sm
                "
              />
              <MagnifyingGlassIcon className="absolute left-3 top-2.5 h-5 w-5 text-gray-400" />
            </form>
          </div>

          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center space-x-3">
            {isAuthenticated ? (
              <>
                {/* Create Listing Button */}
                <Link
                  to="/create-listing"
                  className="
                    inline-flex items-center px-4 py-2 
                    border border-transparent text-sm font-medium rounded-lg
                    text-white bg-primary-600 
                    hover:bg-primary-700 
                    focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500
                    transition-all duration-200
                    touch-manipulation
                  "
                >
                  <PlusIcon className="w-4 h-4 mr-1.5" />
                  Sell
                </Link>

                {/* Notifications */}
                <Link
                  to="/notifications"
                  className="
                    relative p-2 
                    text-gray-600 hover:text-gray-900 
                    focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 rounded-full
                    transition-colors duration-200
                  "
                  aria-label={`Notifications${unreadCount > 0 ? `, ${unreadCount} unread` : ''}`}
                >
                  <BellIcon className="w-6 h-6" />
                  {unreadCount > 0 && (
                    <span 
                      className="
                        absolute -top-0.5 -right-0.5 
                        h-5 w-5 bg-error text-white text-xs font-bold rounded-full 
                        flex items-center justify-center
                        animate-pulse
                      "
                    >
                      {unreadCount > 99 ? '99+' : unreadCount}
                    </span>
                  )}
                </Link>

                {/* Profile Menu */}
                <div className="relative" ref={profileMenuRef}>
                  <button
                    onClick={() => setIsProfileMenuOpen(!isProfileMenuOpen)}
                    className="
                      flex items-center space-x-2 p-1.5 
                      rounded-full hover:bg-gray-100 
                      focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500
                      transition-colors duration-200
                    "
                    aria-expanded={isProfileMenuOpen}
                    aria-haspopup="true"
                  >
                    {user?.profilePhoto ? (
                      <img
                        src={user.profilePhoto}
                        alt={user.firstName}
                        className="w-8 h-8 rounded-full object-cover"
                      />
                    ) : (
                      <div className="w-8 h-8 bg-gray-200 rounded-full flex items-center justify-center">
                        <UserIcon className="w-5 h-5 text-gray-600" />
                      </div>
                    )}
                    <span className="text-sm font-medium text-gray-700 hidden lg:block">
                      {user?.firstName}
                    </span>
                  </button>

                  {/* Profile Dropdown */}
                  {isProfileMenuOpen && (
                    <div 
                      className="
                        absolute right-0 mt-2 w-56 
                        bg-white rounded-xl shadow-lg 
                        ring-1 ring-black ring-opacity-5 
                        focus:outline-none
                        animate-fade-in
                      "
                      role="menu"
                      aria-orientation="vertical"
                    >
                      <div className="py-1">
                        <div className="px-4 py-3 border-b border-gray-100">
                          <p className="text-sm font-medium text-gray-900">
                            {user?.firstName} {user?.lastName}
                          </p>
                          <p className="text-sm text-gray-500 truncate">{user?.email}</p>
                          {user?.trustScore && (
                            <div className="flex items-center mt-2">
                              <span className="text-xs text-gray-500">Trust Score:</span>
                              <span className="ml-2 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                                {user.trustScore.total}%
                              </span>
                            </div>
                          )}
                        </div>
                        
                        <Link
                          to="/profile"
                          className="
                            flex items-center px-4 py-2.5 
                            text-sm text-gray-700 hover:bg-gray-50 
                            transition-colors duration-150
                          "
                          onClick={() => setIsProfileMenuOpen(false)}
                          role="menuitem"
                        >
                          <UserIcon className="w-4 h-4 mr-3" />
                          Profile
                        </Link>
                        
                        <Link
                          to="/dashboard"
                          className="
                            flex items-center px-4 py-2.5 
                            text-sm text-gray-700 hover:bg-gray-50 
                            transition-colors duration-150
                          "
                          onClick={() => setIsProfileMenuOpen(false)}
                          role="menuitem"
                        >
                          <Cog6ToothIcon className="w-4 h-4 mr-3" />
                          Dashboard
                        </Link>
                        
                        <button
                          onClick={handleLogout}
                          className="
                            flex items-center w-full px-4 py-2.5 
                            text-sm text-gray-700 hover:bg-gray-50 
                            transition-colors duration-150
                          "
                          role="menuitem"
                        >
                          <ArrowRightOnRectangleIcon className="w-4 h-4 mr-3" />
                          Sign out
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </>
            ) : (
              <>
                <Link
                  to="/login"
                  className="
                    px-4 py-2 
                    text-gray-600 hover:text-gray-900 
                    text-sm font-medium rounded-lg
                    transition-colors duration-200
                  "
                >
                  Sign in
                </Link>
                <Link
                  to="/register"
                  className="
                    px-4 py-2 
                    text-white bg-primary-600 hover:bg-primary-700 
                    text-sm font-medium rounded-lg
                    transition-colors duration-200
                  "
                >
                  Sign up
                </Link>
              </>
            )}
          </div>

          {/* Mobile menu button */}
          <div className="md:hidden">
            <button
              onClick={toggleMenu}
              className="
                p-2 rounded-lg 
                text-gray-600 hover:text-gray-900 hover:bg-gray-100 
                focus:outline-none focus:ring-2 focus:ring-inset focus:ring-primary-500
                transition-colors duration-200
              "
              aria-expanded={isMenuOpen}
              aria-controls="mobile-menu"
              aria-label={isMenuOpen ? 'Close menu' : 'Open menu'}
            >
              {isMenuOpen ? (
                <XMarkIcon className="h-6 w-6" />
              ) : (
                <Bars3Icon className="h-6 w-6" />
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Search Bar */}
      <div className="md:hidden px-4 pb-3">
        <form onSubmit={handleSearch}>
          <label htmlFor="mobile-search" className="sr-only">Search</label>
          <div className="relative">
            <input
              id="mobile-search"
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search for items..."
              className="
                w-full pl-10 pr-4 py-2.5 
                border border-gray-300 rounded-lg
                focus:ring-2 focus:ring-primary-500 focus:border-primary-500
                transition-all duration-200 text-base
              />
            <MagnifyingGlassIcon className="absolute left-3 top-3 h-5 w-5 text-gray-400" />
          </div>
        </form>
      </div>

      {/* Mobile Navigation Menu */}
      {isMenuOpen && (
        <div 
          id="mobile-menu"
          className="md:hidden"
          ref={menuRef}
        >
          <div className="px-2 pt-2 pb-3 space-y-1 bg-white border-t border-gray-200">
            {isAuthenticated ? (
              <>
                <MobileNavLink
                  to="/"
                  onClick={() => setIsMenuOpen(false)}
                  isActive={isActive('/')}
                  icon={
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
                    </svg>
                  }
                >
                  Home
                </MobileNavLink>
                
                <MobileNavLink
                  to="/create-listing"
                  onClick={() => setIsMenuOpen(false)}
                  isActive={isActive('/create-listing')}
                  icon={
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                    </svg>
                  }
                >
                  Create Listing
                </MobileNavLink>
                
                <MobileNavLink
                  to="/messages"
                  onClick={() => setIsMenuOpen(false)}
                  isActive={isActive('/messages')}
                  icon={
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
                    </svg>
                  }
                  badge={unreadCount}
                >
                  Messages
                </MobileNavLink>
                
                <MobileNavLink
                  to="/profile"
                  onClick={() => setIsMenuOpen(false)}
                  isActive={isActive('/profile')}
                  icon={
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                    </svg>
                  }
                >
                  Profile
                </MobileNavLink>
                
                <MobileNavLink
                  to="/dashboard"
                  onClick={() => setIsMenuOpen(false)}
                  isActive={isActive('/dashboard')}
                  icon={
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" />
                    </svg>
                  }
                >
                  Dashboard
                </MobileNavLink>
                
                <button
                  onClick={handleLogout}
                  className="
                    flex items-center w-full px-3 py-3 
                    text-base font-medium rounded-lg
                    text-gray-600 hover:text-gray-900 hover:bg-gray-50
                    transition-colors duration-200
                  "
                >
                  <ArrowRightOnRectangleIcon className="w-5 h-5 mr-3" />
                  Sign out
                </button>
              </>
            ) : (
              <>
                <MobileNavLink
                  to="/login"
                  onClick={() => setIsMenuOpen(false)}
                  isActive={isActive('/login')}
                  icon={
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1" />
                    </svg>
                  }
                >
                  Sign in
                </MobileNavLink>
                
                <Link
                  to="/register"
                  onClick={() => setIsMenuOpen(false)}
                  className="
                    flex items-center mx-2 px-4 py-3 
                    text-base font-medium rounded-lg
                    text-white bg-primary-600 hover:bg-primary-700
                    transition-colors duration-200
                  "
                >
                  Sign up
                </Link>
              </>
            )}
          </div>
        </div>
      )}
    </header>
  );
});

// Mobile navigation link component
const MobileNavLink = memo(({ to, onClick, isActive, icon, children, badge }) => (
  <Link
    to={to}
    onClick={onClick}
    className={`
      flex items-center justify-between px-3 py-3 
      text-base font-medium rounded-lg
      transition-colors duration-200
      ${isActive 
        ? 'text-primary-700 bg-primary-50' 
        : 'text-gray-600 hover:text-gray-900 hover:bg-gray-50'
      }
    `}
    aria-current={isActive ? 'page' : undefined}
  >
    <div className="flex items-center">
      {icon}
      <span className="ml-3">{children}</span>
    </div>
    {badge > 0 && (
      <span className="bg-error text-white text-xs font-bold rounded-full px-2 py-0.5">
        {badge > 99 ? '99+' : badge}
      </span>
    )}
  </Link>
));

MobileNavLink.displayName = 'MobileNavLink';

// Display name for debugging
Header.displayName = 'Header';

export default Header;
