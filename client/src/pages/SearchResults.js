import React from 'react';
import { useSearchParams } from 'react-router-dom';

const SearchResults = () => {
  const [searchParams] = useSearchParams();
  const query = searchParams.get('q') || '';

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">
          Search Results {query && `for "${query}"`}
        </h1>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
        {[...Array(8)].map((_, i) => (
          <div key={i} className="bg-white rounded-lg shadow overflow-hidden hover:shadow-md transition-shadow">
            <div className="bg-gray-200 h-48 flex items-center justify-center">
              <span className="text-gray-500">Product {i + 1}</span>
            </div>
            <div className="p-4">
              <h3 className="text-lg font-semibold mb-2">Sample Product {i + 1}</h3>
              <p className="text-2xl font-bold text-blue-600">₹{(i + 1) * 299}</p>
              <div className="mt-2 flex items-center text-sm text-gray-500">
                <span>Trust Score: 95%</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default SearchResults;