import React from 'react';
import { useParams } from 'react-router-dom';

const Profile = () => {
  // eslint-disable-next-line no-unused-vars
  const { userId } = useParams();

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="bg-white rounded-lg shadow overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-200">
          <div className="flex items-center">
            <div className="w-16 h-16 bg-blue-500 rounded-full flex items-center justify-center">
              <span className="text-2xl font-bold text-white">U</span>
            </div>
            <div className="ml-4">
              <h1 className="text-2xl font-bold text-gray-900">John Doe</h1>
              <p className="text-gray-600">Verified User</p>
              <div className="flex items-center mt-1">
                <span className="bg-green-100 text-green-800 px-2 py-1 rounded-full text-xs font-medium">
                  Trust Score: 98%
                </span>
              </div>
            </div>
          </div>
        </div>

        <div className="p-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <h3 className="text-lg font-semibold mb-4">User Information</h3>
              <div className="space-y-3">
                <div className="flex justify-between">
                  <span className="text-gray-600">Member Since</span>
                  <span className="text-gray-900">January 2024</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Total Listings</span>
                  <span className="text-gray-900">24</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Successful Transactions</span>
                  <span className="text-gray-900">18</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Response Rate</span>
                  <span className="text-gray-900">95%</span>
                </div>
              </div>
            </div>

            <div>
              <h3 className="text-lg font-semibold mb-4">Recent Activity</h3>
              <div className="space-y-3">
                <div className="flex items-center">
                  <div className="w-2 h-2 bg-green-500 rounded-full mr-3"></div>
                  <span className="text-sm text-gray-600">Listed "iPhone 13" - 2 hours ago</span>
                </div>
                <div className="flex items-center">
                  <div className="w-2 h-2 bg-blue-500 rounded-full mr-3"></div>
                  <span className="text-sm text-gray-600">Completed transaction - 1 day ago</span>
                </div>
                <div className="flex items-center">
                  <div className="w-2 h-2 bg-yellow-500 rounded-full mr-3"></div>
                  <span className="text-sm text-gray-600">Video verification completed - 2 days ago</span>
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