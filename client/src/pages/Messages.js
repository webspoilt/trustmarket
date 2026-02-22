import React from 'react';
import { useParams } from 'react-router-dom';

const Messages = () => {
  // eslint-disable-next-line no-unused-vars
  const { conversationId } = useParams();

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="glass-dark border border-slate-700/50 rounded-xl shadow-xl shadow-black/20 overflow-hidden">
        <div className="flex h-96">
          <div className="w-1/3 border-r border-slate-700/50">
            <div className="p-4 border-b border-slate-700/50">
              <h2 className="text-lg font-semibold text-white">Messages</h2>
            </div>
            <div className="overflow-y-auto h-80">
              {[...Array(5)].map((_, i) => (
                <div key={i} className="p-4 border-b border-slate-700/30 hover:bg-slate-800/50 transition-colors cursor-pointer">
                  <div className="flex items-center">
                    <div className="w-10 h-10 bg-slate-700 rounded-full flex items-center justify-center border border-slate-600">
                      <span className="text-sm font-medium text-slate-300">U{i + 1}</span>
                    </div>
                    <div className="ml-3">
                      <p className="text-sm font-medium text-white">User {i + 1}</p>
                      <p className="text-xs text-slate-400">Last message...</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div className="flex-1 flex flex-col">
            <div className="p-4 border-b border-slate-700/50 bg-slate-800/20">
              <h3 className="text-lg font-semibold text-white">Conversation</h3>
            </div>
            <div className="flex-1 p-4 overflow-y-auto bg-slate-900/30">
              <div className="space-y-4">
                <div className="flex">
                  <div className="bg-slate-800 border border-slate-700 rounded-2xl rounded-tl-sm px-4 py-3 max-w-[80%] shadow-md">
                    <p className="text-sm text-slate-300">Hello! I'm interested in your product.</p>
                  </div>
                </div>
                <div className="flex justify-end">
                  <div className="bg-indigo-600 rounded-2xl rounded-tr-sm px-4 py-3 max-w-[80%] shadow-md shadow-indigo-500/20">
                    <p className="text-sm text-white">Hi! Thanks for your interest. It's available.</p>
                  </div>
                </div>
              </div>
            </div>
            <div className="p-4 border-t border-slate-700/50 bg-slate-800/20">
              <div className="flex space-x-2">
                <input
                  type="text"
                  placeholder="Type a message..."
                  className="flex-1 px-4 py-2 bg-slate-800 border border-slate-600 rounded-xl text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 transition-all"
                />
                <button className="bg-indigo-600 text-white px-6 py-2 rounded-xl font-medium hover:bg-indigo-700 transition-colors shadow-lg shadow-indigo-500/30">
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