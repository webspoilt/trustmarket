import React from 'react';
import { useParams } from 'react-router-dom';

const Profile = () => {
  // eslint-disable-next-line no-unused-vars
  const { userId } = useParams();

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="glass-dark border border-slate-700/50 rounded-xl shadow-xl shadow-black/20 overflow-hidden">
        <div className="px-6 py-6 border-b border-slate-700/50 bg-slate-800/30">
          <div className="flex items-center">
            <div className="w-20 h-20 bg-gradient-to-br from-indigo-500 to-fuchsia-500 rounded-full flex items-center justify-center shadow-lg shadow-indigo-500/30 border-2 border-slate-700">
              <span className="text-3xl font-extrabold text-white">U</span>
            </div>
            <div className="ml-6">
              <h1 className="text-3xl font-bold text-white tracking-tight">John Doe</h1>
              <p className="text-indigo-400 font-medium mt-1">Verified User</p>
              <div className="flex items-center mt-3">
                <span className="bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 px-3 py-1 rounded-full text-xs font-bold tracking-wide shadow-[0_0_10px_rgba(16,185,129,0.2)]">
                  Trust Score: 98%
                </span>
              </div>
            </div>
          </div>
        </div>

        <div className="p-8">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div className="bg-slate-800/30 p-6 rounded-xl border border-slate-700/50">
              <h3 className="text-xl font-semibold text-white mb-6">User Information</h3>
              <div className="space-y-4">
                <div className="flex justify-between items-center bg-slate-800/50 p-3 rounded-lg border border-slate-700/30">
                  <span className="text-slate-400">Member Since</span>
                  <span className="text-slate-200 font-medium">January 2024</span>
                </div>
                <div className="flex justify-between items-center bg-slate-800/50 p-3 rounded-lg border border-slate-700/30">
                  <span className="text-slate-400">Total Listings</span>
                  <span className="text-slate-200 font-medium">24</span>
                </div>
                <div className="flex justify-between items-center bg-slate-800/50 p-3 rounded-lg border border-slate-700/30">
                  <span className="text-slate-400">Successful Transactions</span>
                  <span className="text-slate-200 font-medium">18</span>
                </div>
                <div className="flex justify-between items-center bg-slate-800/50 p-3 rounded-lg border border-slate-700/30">
                  <span className="text-slate-400">Response Rate</span>
                  <span className="text-slate-200 font-medium">95%</span>
                </div>
              </div>
            </div>

            <div className="bg-slate-800/30 p-6 rounded-xl border border-slate-700/50">
              <h3 className="text-xl font-semibold text-white mb-6">Recent Activity</h3>
              <div className="space-y-4 relative before:absolute before:inset-0 before:ml-1.5 before:-translate-x-px md:before:mx-auto md:before:translate-x-0 before:h-full before:w-0.5 before:bg-gradient-to-b before:from-transparent before:via-slate-700 before:to-transparent">
                <div className="relative flex items-center gap-4 group">
                  <div className="w-3 h-3 bg-indigo-500 rounded-full z-10 shadow-[0_0_10px_rgba(99,102,241,0.6)] group-hover:scale-125 transition-transform"></div>
                  <div className="bg-slate-800 border border-slate-700 p-3 rounded-lg flex-1">
                    <span className="text-sm text-slate-300 block font-medium">Listed "iPhone 13"</span>
                    <span className="text-xs text-slate-500 block mt-1">2 hours ago</span>
                  </div>
                </div>
                <div className="relative flex items-center gap-4 group">
                  <div className="w-3 h-3 bg-emerald-500 rounded-full z-10 shadow-[0_0_10px_rgba(16,185,129,0.6)] group-hover:scale-125 transition-transform"></div>
                  <div className="bg-slate-800 border border-slate-700 p-3 rounded-lg flex-1">
                    <span className="text-sm text-slate-300 block font-medium">Completed transaction</span>
                    <span className="text-xs text-slate-500 block mt-1">1 day ago</span>
                  </div>
                </div>
                <div className="relative flex items-center gap-4 group">
                  <div className="w-3 h-3 bg-amber-500 rounded-full z-10 shadow-[0_0_10px_rgba(245,158,11,0.6)] group-hover:scale-125 transition-transform"></div>
                  <div className="bg-slate-800 border border-slate-700 p-3 rounded-lg flex-1">
                    <span className="text-sm text-slate-300 block font-medium">Video verification completed</span>
                    <span className="text-xs text-slate-500 block mt-1">2 days ago</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Profile;