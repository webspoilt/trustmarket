import React from 'react';

const Dashboard = () => {
  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white">Dashboard</h1>
        <p className="text-slate-400">Manage your TrustMarket account</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <div className="glass-dark border border-slate-700/50 rounded-lg p-6 shadow-xl shadow-black/20">
          <div className="flex items-center">
            <div className="w-12 h-12 bg-indigo-900/40 rounded-full flex items-center justify-center border border-indigo-500/20">
              <svg className="w-6 h-6 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.746 0 3.332.477 4.5 1.253v13C19.832 18.477 18.246 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
              </svg>
            </div>
            <div className="ml-4">
              <p className="text-2xl font-bold text-white">24</p>
              <p className="text-sm text-slate-400">Active Listings</p>
            </div>
          </div>
        </div>

        <div className="glass-dark border border-slate-700/50 rounded-lg p-6 shadow-xl shadow-black/20">
          <div className="flex items-center">
            <div className="w-12 h-12 bg-green-900/40 rounded-full flex items-center justify-center border border-green-500/20">
              <svg className="w-6 h-6 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <div className="ml-4">
              <p className="text-2xl font-bold text-white">18</p>
              <p className="text-sm text-slate-400">Completed Sales</p>
            </div>
          </div>
        </div>

        <div className="glass-dark border border-slate-700/50 rounded-lg p-6 shadow-xl shadow-black/20">
          <div className="flex items-center">
            <div className="w-12 h-12 bg-amber-900/40 rounded-full flex items-center justify-center border border-amber-500/20">
              <svg className="w-6 h-6 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
              </svg>
            </div>
            <div className="ml-4">
              <p className="text-2xl font-bold text-white">32</p>
              <p className="text-sm text-slate-400">Messages</p>
            </div>
          </div>
        </div>

        <div className="glass-dark border border-slate-700/50 rounded-lg p-6 shadow-xl shadow-black/20">
          <div className="flex items-center">
            <div className="w-12 h-12 bg-purple-900/40 rounded-full flex items-center justify-center border border-purple-500/20">
              <svg className="w-6 h-6 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z" />
              </svg>
            </div>
            <div className="ml-4">
              <p className="text-2xl font-bold text-white">98%</p>
              <p className="text-sm text-slate-400">Trust Score</p>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="glass-dark border border-slate-700/50 rounded-lg shadow-xl">
          <div className="px-6 py-4 border-b border-slate-700/50">
            <h3 className="text-lg font-semibold text-white">Recent Activity</h3>
          </div>
          <div className="p-6">
            <div className="space-y-4">
              {[...Array(5)].map((_, i) => (
                <div key={i} className="flex items-center">
                  <div className="w-2 h-2 bg-indigo-500 rounded-full mr-3 shadow-[0_0_8px_rgba(99,102,241,0.6)]"></div>
                  <span className="text-sm text-slate-400">Activity {i + 1}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="glass-dark border border-slate-700/50 rounded-lg shadow-xl">
          <div className="px-6 py-4 border-b border-slate-700/50">
            <h3 className="text-lg font-semibold text-white">Quick Actions</h3>
          </div>
          <div className="p-6 space-y-3">
            <button className="w-full bg-indigo-600 text-white px-4 py-3 rounded-xl hover:bg-indigo-700 transition-colors shadow-lg shadow-indigo-500/20 font-medium">
              Create New Listing
            </button>
            <button className="w-full bg-slate-800/50 border border-slate-600 text-slate-200 px-4 py-3 rounded-xl hover:bg-slate-700 transition-colors font-medium">
              View Messages
            </button>
            <button className="w-full bg-slate-800/50 border border-slate-600 text-slate-200 px-4 py-3 rounded-xl hover:bg-slate-700 transition-colors font-medium">
              Edit Profile
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;