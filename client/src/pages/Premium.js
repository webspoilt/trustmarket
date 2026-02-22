import React from 'react';

const Premium = () => {
  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="text-center mb-12">
        <h1 className="text-4xl font-extrabold text-white mb-4 tracking-tight">Upgrade to Premium</h1>
        <p className="text-xl text-slate-400 max-w-2xl mx-auto">Get advanced features and boost your marketplace success</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Basic Plan */}
        <div className="glass-dark border border-slate-700/50 rounded-2xl shadow-xl p-8 hover:-translate-y-2 transition-transform duration-300">
          <div className="text-center mb-8">
            <h3 className="text-xl font-bold text-slate-300">Basic</h3>
            <div className="mt-4">
              <span className="text-5xl font-extrabold text-white">Free</span>
            </div>
          </div>
          <ul className="space-y-4 mb-8">
            <li className="flex items-center">
              <svg className="w-6 h-6 text-emerald-400 mr-3 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
              <span className="text-slate-300">Basic listing creation</span>
            </li>
            <li className="flex items-center">
              <svg className="w-6 h-6 text-emerald-400 mr-3 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
              <span className="text-slate-300">Standard messaging</span>
            </li>
            <li className="flex items-center">
              <svg className="w-6 h-6 text-emerald-400 mr-3 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
              <span className="text-slate-300">Basic verification</span>
            </li>
          </ul>
          <button className="w-full bg-slate-800 text-slate-300 border border-slate-600 px-6 py-3 rounded-xl hover:bg-slate-700 hover:text-white transition-all font-medium">
            Current Plan
          </button>
        </div>

        {/* Premium Plan (Popular) */}
        <div className="glass-dark border-2 border-indigo-500 rounded-2xl shadow-[0_0_30px_rgba(99,102,241,0.2)] p-8 relative hover:-translate-y-2 transition-transform duration-300 transform scale-105 z-10 bg-slate-800/80">
          <div className="absolute -top-4 left-1/2 transform -translate-x-1/2">
            <span className="bg-gradient-to-r from-indigo-500 to-purple-500 text-white px-6 py-1.5 rounded-full text-sm font-bold shadow-lg shadow-indigo-500/30">MOST POPULAR</span>
          </div>
          <div className="text-center mb-8 mt-4">
            <h3 className="text-xl font-bold text-indigo-300">Premium</h3>
            <div className="mt-4 flex items-baseline justify-center">
              <span className="text-5xl font-extrabold text-white">₹299</span>
              <span className="text-slate-400 ml-2">/month</span>
            </div>
          </div>
          <ul className="space-y-4 mb-8">
            <li className="flex items-center">
              <svg className="w-6 h-6 text-indigo-400 mr-3 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
              <span className="text-slate-200">Everything in Basic</span>
            </li>
            <li className="flex items-center">
              <svg className="w-6 h-6 text-indigo-400 mr-3 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
              <span className="text-slate-200 font-medium">Priority listings</span>
            </li>
            <li className="flex items-center">
              <svg className="w-6 h-6 text-indigo-400 mr-3 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
              <span className="text-slate-200 font-medium">Advanced analytics</span>
            </li>
            <li className="flex items-center">
              <svg className="w-6 h-6 text-indigo-400 mr-3 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
              <span className="text-slate-200 font-medium">24/7 priority support</span>
            </li>
          </ul>
          <button className="w-full bg-indigo-600 text-white px-6 py-3.5 rounded-xl font-bold hover:bg-indigo-700 hover:shadow-lg hover:shadow-indigo-500/30 transition-all active:scale-95">
            Upgrade to Premium
          </button>
        </div>

        {/* Pro Plan */}
        <div className="glass-dark border border-slate-700/50 rounded-2xl shadow-xl p-8 hover:-translate-y-2 transition-transform duration-300">
          <div className="text-center mb-8">
            <h3 className="text-xl font-bold text-fuchsia-400">Pro</h3>
            <div className="mt-4 flex items-baseline justify-center">
              <span className="text-5xl font-extrabold text-white">₹599</span>
              <span className="text-slate-400 ml-2">/month</span>
            </div>
          </div>
          <ul className="space-y-4 mb-8">
            <li className="flex items-center">
              <svg className="w-6 h-6 text-fuchsia-400 mr-3 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
              <span className="text-slate-200">Everything in Premium</span>
            </li>
            <li className="flex items-center">
              <svg className="w-6 h-6 text-fuchsia-400 mr-3 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
              <span className="text-slate-200">Unlimited listings</span>
            </li>
            <li className="flex items-center">
              <svg className="w-6 h-6 text-fuchsia-400 mr-3 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
              <span className="text-slate-200">Custom branding</span>
            </li>
            <li className="flex items-center">
              <svg className="w-6 h-6 text-fuchsia-400 mr-3 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
              <span className="text-slate-200">Full API access</span>
            </li>
          </ul>
          <button className="w-full bg-slate-800 text-fuchsia-400 border border-fuchsia-500/50 px-6 py-3 rounded-xl hover:bg-fuchsia-600 hover:text-white hover:border-fuchsia-600 transition-all font-medium">
            Get Pro Access
          </button>
        </div>
      </div>
    </div>
  );
};

export default Premium;