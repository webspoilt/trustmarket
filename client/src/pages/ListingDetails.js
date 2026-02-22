import React from 'react';
import { useParams } from 'react-router-dom';

const ListingDetails = () => {
  // eslint-disable-next-line no-unused-vars
  const { id } = useParams();

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="glass-dark border border-slate-700/50 rounded-xl shadow-xl shadow-black/20 overflow-hidden">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 p-6">
          <div>
            <div className="bg-slate-800/50 border border-slate-600/50 rounded-xl h-64 flex items-center justify-center shadow-inner">
              <span className="text-slate-500 font-medium">Product Image Gallery</span>
            </div>
          </div>
          <div>
            <h1 className="text-3xl font-bold text-white mb-4">Product Title</h1>
            <p className="text-4xl font-extrabold text-indigo-400 mb-6 drop-shadow-lg">₹1,299</p>
            <div className="space-y-6">
              <div className="bg-slate-800/30 p-4 rounded-xl border border-slate-700/30">
                <h3 className="text-lg font-semibold text-slate-200 mb-2 flex items-center gap-2">
                  <svg className="w-5 h-5 text-indigo-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                  Description
                </h3>
                <p className="text-slate-400 leading-relaxed max-w-prose">This is a sample product description. The actual content will be loaded based on the listing ID.</p>
              </div>
              <div className="bg-slate-800/30 p-4 rounded-xl border border-slate-700/30">
                <h3 className="text-lg font-semibold text-slate-200 mb-2 flex items-center gap-2">
                  <svg className="w-5 h-5 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
                  Seller Information
                </h3>
                <p className="text-slate-400">Seller name and trust score will be displayed here.</p>
              </div>
              <div className="flex flex-col sm:flex-row gap-4 pt-4">
                <button className="flex-1 bg-indigo-600 text-white px-6 py-3 rounded-xl font-bold hover:bg-indigo-700 transition-all shadow-lg shadow-indigo-500/30 hover:scale-[1.02]">
                  Contact Seller
                </button>
                <button className="flex-1 bg-slate-800 border border-slate-600 text-slate-300 px-6 py-3 rounded-xl font-medium hover:bg-slate-700 hover:text-white transition-all">
                  Report Listing
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ListingDetails;