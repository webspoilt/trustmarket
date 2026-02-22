import React from 'react';
import { useNavigate } from 'react-router-dom';

const MobileLayout = ({ children }) => {
  const navigate = useNavigate();

  const handleBack = () => {
    if (window.history.length > 1) {
      navigate(-1);
    } else {
      navigate('/');
    }
  };

  return (
    <div className="min-h-screen bg-slate-900 flex flex-col">
      {/* Mobile Header */}
      <header className="fixed top-0 left-0 right-0 glass-dark border-b border-slate-700/50 z-50">
        <div className="flex items-center justify-between px-4 h-14">
          <button
            onClick={handleBack}
            className="p-2 -ml-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-full transition-colors"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
          </button>
          <h1 className="text-lg font-semibold text-white">TrustMarket</h1>
          <div className="w-9"></div> {/* Spacer for centering */}
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 pt-14 pb-16">
        {children}
      </main>

      {/* Bottom Navigation */}
      <nav className="fixed bottom-0 left-0 right-0 glass-dark border-t border-slate-700/50 z-50">
        <div className="flex items-center justify-around px-2 py-1">
          <button
            onClick={() => navigate('/')}
            className="flex flex-col items-center justify-center py-2 px-3 min-w-[64px] text-xs font-medium text-slate-400 hover:text-indigo-400 transition-colors"
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
            </svg>
            <span className="mt-1">Home</span>
          </button>

          <button
            onClick={() => navigate('/search')}
            className="flex flex-col items-center justify-center py-2 px-3 min-w-[64px] text-xs font-medium text-slate-400 hover:text-indigo-400 transition-colors"
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <span className="mt-1">Search</span>
          </button>

          <button
            onClick={() => navigate('/create-listing')}
            className="relative -top-4 w-14 h-14 bg-indigo-600 rounded-full flex items-center justify-center shadow-lg shadow-indigo-500/30 transition-transform hover:scale-105 active:scale-95"
          >
            <svg className="w-7 h-7 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M12 4v16m8-8H4" />
            </svg>
          </button>

          <button
            onClick={() => navigate('/messages')}
            className="flex flex-col items-center justify-center py-2 px-3 min-w-[64px] text-xs font-medium text-slate-400 hover:text-indigo-400 transition-colors"
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
            </svg>
            <span className="mt-1">Chat</span>
          </button>

          <button
            onClick={() => navigate('/profile')}
            className="flex flex-col items-center justify-center py-2 px-3 min-w-[64px] text-xs font-medium text-slate-400 hover:text-indigo-400 transition-colors"
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
            </svg>
            <span className="mt-1">Profile</span>
          </button>
        </div>
      </nav>
    </div>
  );
};

export default MobileLayout;