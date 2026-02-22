import React from 'react';
import { useParams } from 'react-router-dom';

const ListingDetails = () => {
  // eslint-disable-next-line no-unused-vars
  const { id } = useParams();

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="bg-white rounded-lg shadow overflow-hidden">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 p-6">
          <div>
            <div className="bg-gray-200 rounded-lg h-64 flex items-center justify-center">
              <span className="text-gray-500">Product Image</span>
            </div>
          </div>
          <div>
            <h1 className="text-2xl font-bold text-gray-900 mb-4">Product Title</h1>
            <p className="text-3xl font-bold text-blue-600 mb-4">₹1,299</p>
            <div className="space-y-4">
              <div>
                <h3 className="text-lg font-semibold mb-2">Description</h3>
                <p className="text-gray-600">This is a sample product description. The actual content will be loaded based on the listing ID.</p>
              </div>
              <div>
                <h3 className="text-lg font-semibold mb-2">Seller Information</h3>
                <p className="text-gray-600">Seller name and trust score will be displayed here.</p>
              </div>
              <div className="flex space-x-4">
                <button className="bg-blue-600 text-white px-6 py-2 rounded-md hover:bg-blue-700 transition-colors">
                  Contact Seller
                </button>
                <button className="border border-gray-300 text-gray-700 px-6 py-2 rounded-md hover:bg-gray-50 transition-colors">
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