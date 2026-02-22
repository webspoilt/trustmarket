import React from 'react';

const CreateListing = () => {
  return (
    <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="glass-dark border border-slate-700/50 rounded-xl shadow-xl shadow-black/20 p-6">
        <h1 className="text-2xl font-bold text-white mb-6">Create New Listing</h1>
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Product Name
              </label>
              <input
                type="text"
                className="w-full px-4 py-3 bg-slate-800/50 border border-slate-600 rounded-xl text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all"
                placeholder="Enter product name"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Price (₹)
              </label>
              <input
                type="number"
                className="w-full px-4 py-3 bg-slate-800/50 border border-slate-600 rounded-xl text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all"
                placeholder="Enter price"
              />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Description
            </label>
            <textarea
              rows="4"
              className="w-full px-4 py-3 bg-slate-800/50 border border-slate-600 rounded-xl text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all"
              placeholder="Describe your product"
            ></textarea>
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Category
            </label>
            <select className="w-full px-4 py-3 bg-slate-800/50 border border-slate-600 rounded-xl text-white focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all appearance-none">
              <option value="electronics" className="bg-slate-800">Electronics</option>
              <option value="vehicles" className="bg-slate-800">Vehicles</option>
              <option value="furniture" className="bg-slate-800">Furniture</option>
              <option value="books" className="bg-slate-800">Books</option>
              <option value="clothing" className="bg-slate-800">Clothing</option>
              <option value="services" className="bg-slate-800">Services</option>
              <option value="jobs" className="bg-slate-800">Jobs</option>
              <option value="real_estate" className="bg-slate-800">Real Estate</option>
              <option value="other" className="bg-slate-800">Other</option>
            </select>
          </div>

          <div className="flex justify-end pt-4">
            <button className="bg-indigo-600 text-white px-8 py-3 rounded-xl font-bold hover:bg-indigo-700 hover:scale-105 transition-all duration-300 shadow-lg shadow-indigo-500/30">
              Create Listing
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CreateListing;