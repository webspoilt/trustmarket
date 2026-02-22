import React from 'react';
import { Link } from 'react-router-dom';

const NotFound = () => {
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full text-center">
        <div className="mb-8">
          <div className="w-24 h-24 mx-auto bg-gray-200 rounded-full flex items-center justify-center mb-6">
            <svg className="w-12 h-12 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.172 16.172a4 4 0 015.656 0M9 12h6m-6-4h6m2 5.291A7.962 7.962 0 0112 15c-2.34 0-4.29-1.207-5.428-3.02L3 20l1.572-4.291A7.962 7.962 0 0112 15z" />
            </svg>
          </div>
          <h1 className="text-6xl font-bold text-gray-300 mb-4">404</h1>
          <h2 className="text-2xl font-bold text-gray-900 mb-2">Page Not Found</h2>
          <p className="text-gray-600 mb-8">
            Sorry, we couldn't find the page you're looking for. It might have been moved, deleted, or the URL might be incorrect.
          </p>
        </div>

        <div className="space-y-4">
          <Link
            to="/"
            className="block w-full bg-blue-600 text-white px-6 py-3 rounded-md hover:bg-blue-700 transition-colors font-medium"
          >
            Go to Homepage
          </Link>
          <button
            onClick={() => window.history.back()}
            className="block w-full border border-gray-300 text-gray-700 px-6 py-3 rounded-md hover:bg-gray-50 transition-colors font-medium"
          >
            Go Back
          </button>
        </div>

        <div className="mt-8 pt-6 border-t border-gray-200">
          <p className="text-sm text-gray-500">
            Need help? Visit our{' '}
            <button type="button" className="text-blue-600 hover:text-blue-500 bg-transparent border-none cursor-pointer">
              help center
            </button>{' '}
            or{' '}
            <button type="button" className="text-blue-600 hover:text-blue-500 bg-transparent border-none cursor-pointer">
              contact support
            </button>
          </p>
        </div>
      </div>
    </div>
  );
};

export default NotFound;