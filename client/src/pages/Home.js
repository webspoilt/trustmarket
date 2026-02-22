import React, { useState, Suspense } from 'react';
import { Link, useNavigate } from 'react-router-dom';

// Lazy load the 3D globe (heavy dependency)
const SecureGlobe = React.lazy(() => import('../components/visual/SecureGlobe'));

const Home = () => {
  const [searchQuery, setSearchQuery] = useState('');
  const navigate = useNavigate();

  const handleSearch = (e) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      navigate(`/search?q=${encodeURIComponent(searchQuery.trim())}`);
    }
  };

  return (
    <div className="min-h-screen">
      {/* ═══ HERO SECTION ═══ */}
      <div className="relative min-h-[90vh] flex items-center justify-center overflow-hidden bg-gradient-to-b from-slate-900 via-indigo-950 to-slate-900">

        {/* 3D Globe Background */}
        <Suspense fallback={null}>
          <SecureGlobe />
        </Suspense>

        {/* Gradient overlay for text readability */}
        <div className="absolute inset-0 bg-gradient-to-b from-transparent via-slate-900/30 to-slate-900/80 z-[1]"></div>

        {/* Hero Content */}
        <div className="relative z-10 text-center px-4 max-w-5xl mx-auto">

          {/* Security Badge */}
          <div className="inline-block mb-6 px-4 py-1.5 bg-green-500/15 border border-green-500/30 rounded-full text-green-300 text-sm font-medium backdrop-blur-sm animate-fade-in-up">
            <span className="mr-2">🛡️</span> Quantum Resistant Encryption Active
          </div>

          <h1 className="text-4xl sm:text-6xl lg:text-7xl font-extrabold text-white mb-4 tracking-tight animate-fade-in-up" style={{ animationDelay: '0.1s' }}>
            Trust<span className="bg-gradient-to-r from-indigo-400 to-purple-400 bg-clip-text text-transparent">Market</span>
            <span className="text-indigo-400 text-3xl sm:text-4xl lg:text-5xl ml-2 font-light">3.0</span>
          </h1>

          <p className="text-lg sm:text-xl text-slate-300 max-w-2xl mx-auto mb-10 animate-fade-in-up" style={{ animationDelay: '0.2s' }}>
            India's most secure P2P marketplace. Protected by Argon2id cryptography, behavioral analysis, and real-time anomaly detection.
          </p>

          {/* Glass Search Bar */}
          <form onSubmit={handleSearch} className="max-w-xl mx-auto mb-12 animate-fade-in-up" style={{ animationDelay: '0.3s' }}>
            <div className="glass-dark rounded-2xl p-2 flex items-center shadow-2xl shadow-indigo-500/10">
              <svg className="w-5 h-5 text-slate-400 ml-3 mr-2 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
              <input
                type="text"
                placeholder="Search for electronics, vehicles, fashion..."
                className="flex-1 bg-transparent text-white placeholder-slate-400 py-3 px-2 outline-none text-sm sm:text-base"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
              <button type="submit" className="btn-primary !py-2.5 !px-6 !rounded-xl text-sm font-semibold">
                Search
              </button>
            </div>
          </form>

          {/* Security Feature Cards */}
          <div className="grid md:grid-cols-3 gap-4 sm:gap-6 max-w-4xl mx-auto text-left stagger-children">
            <div className="glass-dark rounded-2xl p-6 border border-indigo-500/20 hover:-translate-y-1 transition-all duration-300 shadow-xl shadow-indigo-500/10">
              <div className="text-indigo-400 mb-3">
                <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
              </div>
              <h3 className="text-white font-bold mb-1">Argon2id Hashing</h3>
              <p className="text-xs text-slate-400 leading-relaxed">Memory-hard algorithms defeat GPU cracking attacks.</p>
            </div>

            <div className="glass-dark rounded-2xl p-6 border border-purple-500/20 hover:-translate-y-1 transition-all duration-300 shadow-xl shadow-purple-500/10">
              <div className="text-purple-400 mb-3">
                <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
              </div>
              <h3 className="text-white font-bold mb-1">Behavioral Physics</h3>
              <p className="text-xs text-slate-400 leading-relaxed">Euclidean distance vectors analyze human vs bot behavior.</p>
            </div>

            <div className="glass-dark rounded-2xl p-6 border border-cyan-500/20 hover:-translate-y-1 transition-all duration-300 shadow-xl shadow-cyan-500/10">
              <div className="text-cyan-400 mb-3">
                <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </div>
              <h3 className="text-white font-bold mb-1">Entropy Analysis</h3>
              <p className="text-xs text-slate-400 leading-relaxed">Shannon Entropy calculates password strength mathematically.</p>
            </div>
          </div>

          <div className="mt-12 animate-fade-in-up" style={{ animationDelay: '0.6s' }}>
            <Link
              to="/register"
              className="inline-block px-8 py-4 bg-indigo-600 text-white font-bold rounded-full text-lg hover:bg-indigo-700 transition-all duration-300 shadow-lg shadow-indigo-500/30 hover:shadow-indigo-500/50 hover:scale-105"
            >
              Join Secure Network
            </Link>
          </div>
        </div>
      </div>

      {/* ═══ CATEGORIES SECTION ═══ */}
      <div className="max-w-7xl mx-auto px-4 -mt-12 relative z-20 pb-16">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 stagger-children">
          {[
            { name: 'Electronics', emoji: '📱', color: 'from-blue-500 to-cyan-400' },
            { name: 'Vehicles', emoji: '🚗', color: 'from-purple-500 to-pink-400' },
            { name: 'Real Estate', emoji: '🏠', color: 'from-green-500 to-teal-400' },
            { name: 'Fashion', emoji: '👗', color: 'from-orange-500 to-red-400' },
          ].map((cat) => (
            <Link
              key={cat.name}
              to={`/search?category=${cat.name.toLowerCase()}`}
              className="card-neu text-center cursor-pointer group"
            >
              <div
                className={`inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-tr ${cat.color} text-white text-3xl mb-3 group-hover:scale-110 transition-transform duration-300 shadow-md`}
              >
                {cat.emoji}
              </div>
              <h3 className="font-semibold text-slate-700">{cat.name}</h3>
            </Link>
          ))}
        </div>
      </div>

      {/* ═══ WHY TRUSTMARKET ═══ */}
      <div className="relative py-20 overflow-hidden">
        <div className="absolute inset-0 bg-white/50 backdrop-blur-xl"></div>

        <div className="relative max-w-7xl mx-auto px-4">
          <div className="text-center mb-14">
            <h2 className="text-3xl sm:text-4xl font-bold text-slate-900">
              Why Choose TrustMarket?
            </h2>
            <p className="mt-3 text-slate-600 max-w-lg mx-auto">
              Features designed for your safety and trust.
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8 stagger-children">
            {[
              {
                icon: (
                  <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 3v4M3 5h4M6 17v4m-2-2h4m5-16l2.286 6.857L21 12l-5.714 2.143L13 21l-2.286-6.857L5 12l5.714-2.143L13 3z" />
                  </svg>
                ),
                title: 'AI Safety Score',
                desc: 'Every seller is rated by our AI based on transaction history and verification status.',
                color: 'text-purple-500',
                bg: 'bg-purple-50'
              },
              {
                icon: (
                  <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                ),
                title: 'Video Verification',
                desc: 'See the product live before you buy. No stock photos allowed, only genuine videos.',
                color: 'text-blue-500',
                bg: 'bg-blue-50'
              },
              {
                icon: (
                  <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                  </svg>
                ),
                title: 'Instant Alerts',
                desc: 'Real-time notifications the moment your item is listed, viewed, or sold.',
                color: 'text-amber-500',
                bg: 'bg-amber-50'
              },
            ].map((feature, i) => (
              <div
                key={i}
                className="glass rounded-2xl p-6 hover:scale-[1.03] transition-transform duration-300"
              >
                <div className={`inline-flex p-3 rounded-xl ${feature.bg} ${feature.color} mb-4`}>
                  {feature.icon}
                </div>
                <h3 className="text-lg font-bold text-slate-800 mb-2">
                  {feature.title}
                </h3>
                <p className="text-slate-600 text-sm leading-relaxed">
                  {feature.desc}
                </p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ═══ TRUST STATS ═══ */}
      <div className="py-16 px-4">
        <div className="max-w-5xl mx-auto grid grid-cols-2 md:grid-cols-4 gap-6 text-center stagger-children">
          {[
            { value: '50K+', label: 'Active Users', color: 'text-indigo-600' },
            { value: '99.9%', label: 'Uptime', color: 'text-green-600' },
            { value: '10K+', label: 'Verified Sellers', color: 'text-purple-600' },
            { value: '0', label: 'Security Breaches', color: 'text-cyan-600' },
          ].map((stat, i) => (
            <div key={i} className="glass-card p-6">
              <div className={`text-3xl sm:text-4xl font-extrabold ${stat.color} mb-1`}>
                {stat.value}
              </div>
              <div className="text-slate-500 text-sm font-medium">{stat.label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* ═══ FLOATING CTA (Mobile) ═══ */}
      <div className="fixed bottom-6 right-6 z-50 lg:hidden">
        <Link
          to="/create-listing"
          className="flex items-center justify-center w-14 h-14 bg-gradient-to-br from-indigo-500 to-purple-600 text-white text-2xl rounded-full shadow-lg shadow-indigo-500/30 hover:scale-110 transition-transform"
        >
          +
        </Link>
      </div>
    </div>
  );
};

export default Home;