import React from 'react';
import { useSearchParams } from 'react-router-dom';

const SearchResults = () => {
  const [searchParams] = useSearchParams();
  const query = searchParams.get('q') || '';

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white tracking-tight">
          Search Results {query && <span className="text-indigo-400">for "{query}"</span>}
        </h1>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
        {[...Array(8)].map((_, i) => (
          <div key={i} className="glass-dark border border-slate-700/50 rounded-2xl shadow-xl overflow-hidden hover:shadow-indigo-500/20 hover:border-indigo-500/50 transition-all duration-300 group cursor-pointer">
            <div className="bg-slate-800/50 h-48 flex items-center justify-center border-b border-slate-700/50 group-hover:bg-slate-800 transition-colors">
              <span className="text-slate-500 font-medium tracking-wider">Product Image {i + 1}</span>
            </div>
            <div className="p-6">
              <h3 className="text-lg font-semibold mb-2 text-white group-hover:text-indigo-400 transition-colors">Sample Product {i + 1}</h3>
              <p className="text-2xl font-bold text-indigo-400">₹{(i + 1) * 299}</p>
              <div className="mt-4 flex items-center">
                <span className="bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-2 py-1 rounded text-xs font-bold tracking-wide">Trust Score: 95%</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default SearchResults;