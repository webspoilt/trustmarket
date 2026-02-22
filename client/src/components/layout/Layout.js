import React from 'react';
import { Link, Outlet } from 'react-router-dom';
import Header from './Header';

const Layout = () => {
  return (
    <div className="min-h-screen bg-slate-900 flex flex-col">
      <Header />

      {/* Main Content - Use Outlet for nested routes */}
      <main className="flex-1 pt-16">
        <Outlet />
      </main>

      {/* Footer */}
      <footer className="bg-slate-900 border-t border-slate-800/50 relative z-10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="text-center text-slate-400">
            <p>&copy; 2024 TrustMarket. All rights reserved.</p>
            <p className="text-sm mt-2 text-indigo-400 font-medium">India's Safest P2P Marketplace</p>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Layout;