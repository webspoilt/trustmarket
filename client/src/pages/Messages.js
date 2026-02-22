import React from 'react';
import { useParams } from 'react-router-dom';

const Messages = () => {
  // eslint-disable-next-line no-unused-vars
  const { conversationId } = useParams();

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="bg-white rounded-lg shadow overflow-hidden">
        <div className="flex h-96">
          <div className="w-1/3 border-r border-gray-200">
            <div className="p-4 border-b border-gray-200">
              <h2 className="text-lg font-semibold">Messages</h2>
            </div>
            <div className="overflow-y-auto h-80">
              {[...Array(5)].map((_, i) => (
                <div key={i} className="p-4 border-b border-gray-100 hover:bg-gray-50 cursor-pointer">
                  <div className="flex items-center">
                    <div className="w-10 h-10 bg-gray-300 rounded-full flex items-center justify-center">
                      <span className="text-sm font-medium">U{i + 1}</span>
                    </div>
                    <div className="ml-3">
                      <p className="text-sm font-medium text-gray-900">User {i + 1}</p>
                      <p className="text-xs text-gray-500">Last message...</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div className="flex-1 flex flex-col">
            <div className="p-4 border-b border-gray-200">
              <h3 className="text-lg font-semibold">Conversation</h3>
            </div>
            <div className="flex-1 p-4 overflow-y-auto">
              <div className="space-y-4">
                <div className="flex">
                  <div className="bg-blue-100 rounded-lg px-3 py-2">
                    <p className="text-sm">Hello! I'm interested in your product.</p>
                  </div>
                </div>
                <div className="flex justify-end">
                  <div className="bg-gray-100 rounded-lg px-3 py-2">
                    <p className="text-sm">Hi! Thanks for your interest. It's available.</p>
                  </div>
                </div>
              </div>
            </div>
            <div className="p-4 border-t border-gray-200">
              <div className="flex space-x-2">
                <input
                  type="text"
                  placeholder="Type a message..."
                  className="flex-1 px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                />
                <button className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700">
                  Send
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Messages;