import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import Logo from '../common/Logo';

const Header = () => {
  const [scrolled, setScrolled] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const { user, isAuthenticated, logout } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    const handleScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const handleLogout = async () => {
    await logout();
    navigate('/');
    setMobileMenuOpen(false);
  };

  return (
    <header
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-500 ${scrolled
        ? 'glass shadow-lg py-2'
        : 'bg-transparent py-4'
        }`}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex items-center justify-between">
        {/* Logo */}
        <Link to="/" className="group hover:scale-105 transition-transform duration-300">
          <Logo className="h-10 w-10" text={true} />
        </Link>

        {/* Desktop Navigation */}
        <nav className="hidden md:flex items-center space-x-6">
          <Link
            to="/search"
            className="text-slate-600 hover:text-indigo-600 font-medium transition-colors duration-200"
          >
            Browse
          </Link>

          {isAuthenticated ? (
            <>
              <Link
                to="/create-listing"
                className="btn-primary text-sm !py-2 !px-4 !shadow-none"
              >
                + Sell Item
              </Link>

              <Link to="/messages" className="relative group">
                <img
                  src={
                    user?.profilePhoto ||
                    `https://ui-avatars.com/api/?name=${user?.firstName || 'U'}&background=6366f1&color=fff`
                  }
                  alt="Profile"
                  className="w-10 h-10 rounded-full border-2 border-white shadow-sm group-hover:border-indigo-300 transition-all duration-200"
                />
                {/* Online indicator */}
                <span className="absolute bottom-0 right-0 w-3 h-3 bg-green-400 border-2 border-white rounded-full"></span>
              </Link>

              <button
                onClick={handleLogout}
                className="text-slate-500 hover:text-red-500 text-sm font-medium transition-colors"
              >
                Logout
              </button>
            </>
          ) : (
            <div className="flex items-center space-x-3">
              <Link
                to="/login"
                className="px-4 py-2 text-slate-600 font-medium hover:text-indigo-600 transition-colors"
              >
                Login
              </Link>
              <Link to="/register" className="btn-primary text-sm !py-2 !px-4">
                Sign Up
              </Link>
            </div>
          )}
        </nav>

        {/* Mobile Menu Toggle */}
        <button
          className="md:hidden p-2 rounded-xl hover:bg-white/50 transition-colors"
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
        >
          <svg className="h-6 w-6 text-slate-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            {mobileMenuOpen ? (
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            ) : (
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
            )}
          </svg>
        </button>
      </div>

      {/* Mobile Menu */}
      {mobileMenuOpen && (
        <div className="md:hidden glass-card mx-4 mt-2 p-4 animate-scale-in">
          <div className="flex flex-col space-y-3">
            <Link to="/search" onClick={() => setMobileMenuOpen(false)} className="px-3 py-2 rounded-lg text-slate-600 hover:bg-indigo-50 hover:text-indigo-600 font-medium">
              Browse
            </Link>
            {isAuthenticated ? (
              <>
                <Link to="/create-listing" onClick={() => setMobileMenuOpen(false)} className="px-3 py-2 rounded-lg text-slate-600 hover:bg-indigo-50 hover:text-indigo-600 font-medium">
                  + Sell Item
                </Link>
                <Link to="/messages" onClick={() => setMobileMenuOpen(false)} className="px-3 py-2 rounded-lg text-slate-600 hover:bg-indigo-50 hover:text-indigo-600 font-medium">
                  Messages
                </Link>
                <button onClick={handleLogout} className="px-3 py-2 rounded-lg text-left text-red-500 hover:bg-red-50 font-medium">
                  Logout
                </button>
              </>
            ) : (
              <>
                <Link to="/login" onClick={() => setMobileMenuOpen(false)} className="px-3 py-2 rounded-lg text-slate-600 hover:bg-indigo-50 hover:text-indigo-600 font-medium">
                  Login
                </Link>
                <Link to="/register" onClick={() => setMobileMenuOpen(false)} className="btn-primary text-sm text-center">
                  Sign Up
                </Link>
              </>
            )}
          </div>
        </div>
      )}
    </header>
  );
};

export default Header;
