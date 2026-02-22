import React from 'react';
import { Link, Outlet } from 'react-router-dom';

const Layout = () => {
  return (
    <div className="min-h-screen bg-gray-50 flex flex-col">
      {/* Header */}
      <header className="bg-white shadow-sm border-b border-gray-200 fixed top-0 left-0 right-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center">
              <h1 className="text-xl font-bold text-blue-600">TrustMarket</h1>
            </div>
            <nav className="hidden md:flex space-x-8">
              <Link to="/" className="text-gray-700 hover:text-blue-600">Home</Link>
              <Link to="/search" className="text-gray-700 hover:text-blue-600">Search</Link>
              <Link to="/dashboard" className="text-gray-700 hover:text-blue-600">Dashboard</Link>
            </nav>
            <div className="flex items-center space-x-4">
              <Link to="/login" className="text-gray-700 hover:text-blue-600">Login</Link>
              <Link to="/register" className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700">
                Sign Up
              </Link>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content - Use Outlet for nested routes */}
      <main className="flex-1 pt-16">
        <Outlet />
      </main>

      {/* Footer */}
      <footer className="bg-white border-t border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="text-center text-gray-600">
            <p>&copy; 2024 TrustMarket. All rights reserved.</p>
            <p className="text-sm mt-2">India's Safest P2P Marketplace</p>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Layout;