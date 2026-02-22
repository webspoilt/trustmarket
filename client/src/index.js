import React from 'react';
import { createRoot } from 'react-dom/client';
import './index.css';
import App from './App';

// Get the root element
const container = document.getElementById('root');

// Create root and render the app
const root = createRoot(container);

root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);

// Remove the hardcoded loading overlay safely after React mounts
setTimeout(() => {
  document.body.classList.add('app-loaded');
}, 100);

// Performance monitoring (reportWebVitals removed)

// Handle online/offline status with app-wide event dispatching
function updateOnlineStatus() {
  const event = new CustomEvent('app-network-change', {
    detail: { isOnline: navigator.onLine }
  });
  window.dispatchEvent(event);

  // Dispatch to React context via global event
  window.dispatchEvent(new CustomEvent(navigator.onLine ? 'app-online' : 'app-offline'));
}

window.addEventListener('online', updateOnlineStatus);
window.addEventListener('offline', updateOnlineStatus);

// Initial network status check
updateOnlineStatus();

// Expose global helper for triggering browser feedback
window.showToast = function (message, type = 'info', duration = 4000) {
  // Create toast element
  const toastId = 'toast-' + Date.now();
  const toast = document.createElement('div');
  toast.id = toastId;
  toast.style.cssText = `
    position: fixed;
    bottom: 80px;
    left: 50%;
    transform: translateX(-50%) translateY(100px);
    background: ${type === 'success' ? '#10B981' : type === 'error' ? '#EF4444' : type === 'warning' ? '#F59E0B' : '#3B82F6'};
    color: white;
    padding: 12px 24px;
    border-radius: 8px;
    box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
    z-index: 10000;
    font-family: Inter, sans-serif;
    font-weight: 500;
    font-size: 14px;
    max-width: 90vw;
    width: max-content;
    opacity: 0;
    transition: all 0.3s ease;
    display: flex;
    align-items: center;
    gap: 8px;
  `;

  const icon = type === 'success'
    ? '<svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>'
    : type === 'error'
      ? '<svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>'
      : '<svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>';

  toast.innerHTML = `${icon}<span>${message}</span>`;
  document.body.appendChild(toast);

  // Trigger animation
  requestAnimationFrame(() => {
    toast.style.transform = 'translateX(-50%) translateY(0)';
    toast.style.opacity = '1';
  });

  // Remove after duration
  setTimeout(() => {
    toast.style.transform = 'translateX(-50%) translateY(100px)';
    toast.style.opacity = '0';
    setTimeout(() => {
      if (document.body.contains(toast)) {
        document.body.removeChild(toast);
      }
    }, 300);
  }, duration);

  return toastId;
};

// Expose global helper for hiding toasts
window.hideToast = function (toastId) {
  const toast = document.getElementById(toastId || 'toast-' + Date.now());
  if (toast) {
    toast.style.transform = 'translateX(-50%) translateY(100px)';
    toast.style.opacity = '0';
    setTimeout(() => {
      if (document.body.contains(toast)) {
        document.body.removeChild(toast);
      }
    }, 300);
  }
};

// Performance optimization: Defer non-critical operations
if ('requestIdleCallback' in window) {
  requestIdleCallback(() => {
    // Load non-critical resources when browser is idle
    console.log('[Performance] Browser idle, deferred operations can proceed');
  });
}
