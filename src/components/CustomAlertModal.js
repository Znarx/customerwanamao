import React from 'react';

export default function CustomAlertModal({ isOpen, onClose, message }) {
    if (!isOpen) return null;

  return (
    <div className="fixed inset-0 flex items-center justify-center bg-black bg-opacity-50 z-50">
      <div className="bg-white p-6 rounded-lg shadow-xl max-w-xs mx-auto">
        <h2 className="text-xl font-bold mb-4 text-gray-800">Cart is Empty</h2>
        <p className="text-gray-700">Please add items to your cart before proceeding to checkout.</p>
        <div className="mt-6 text-right">
          <button
            onClick={onClose}
            className="bg-gray-800 text-white px-4 py-2 rounded-md shadow hover:bg-gray-700"
          >
            Got it!
          </button>
        </div>
      </div>
    </div>
  );
}
