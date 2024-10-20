import React, { useState } from 'react';
import Image from 'next/image';

const Modal = ({ showModal, selectedViand, closeModal, addToCart }) => {
  const [quantity, setQuantity] = useState(1); // State for quantity

  if (!showModal || !selectedViand) return null;

  const handleAddToCart = () => {
    addToCart({ ...selectedViand, quantity }); // Pass both the selected viand and the quantity
    alert(`Added ${quantity} ${selectedViand.name} to cart!`);
    closeModal();
  };

  const increaseQuantity = () => setQuantity((prev) => prev + 1);
  const decreaseQuantity = () => {
    if (quantity > 1) {
      setQuantity((prev) => prev - 1);
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50">
      <div className="bg-white p-8 rounded-lg shadow-xl max-w-md w-full relative flex flex-col">
        <button
          className="absolute top-4 right-4 text-gray-600 text-3xl font-bold hover:text-red-500 transition duration-200"
          onClick={closeModal}
        >
          &times;
        </button>

        <div className="flex flex-col items-center">
          <Image
            src={selectedViand.imageSrc}
            alt={selectedViand.name}
            width={300}
            height={200}
            className="object-cover rounded-lg mb-4 shadow-md border-4 border-orange-300" // Added border and shadow
          />
          <h2 className="text-2xl font-semibold text-gray-800 text-center mb-2">{selectedViand.name}</h2>
          <p className="text-md text-gray-600 text-center mb-1">{selectedViand.description}</p>
          <p className="text-md text-gray-600 text-center mb-4">
            <strong>Serves:</strong> <span className="text-orange-500">{selectedViand.servings} pax</span>
          </p>
          <div className="flex justify-between items-center w-full">
            <p className="text-lg font-bold text-gray-800">₱{selectedViand.price}</p>
            <div className="flex items-center border border-gray-300 rounded-md overflow-hidden">
              <button
                onClick={decreaseQuantity}
                className="px-3 py-1 text-gray-600 transition duration-150 hover:bg-gray-100"
              >
                -
              </button>
              <span className="px-4 text-gray-800">{quantity}</span>
              <button
                onClick={increaseQuantity}
                className="px-3 py-1 text-gray-600 transition duration-150 hover:bg-gray-100"
              >
                +
              </button>
            </div>
            <button
              className="ml-4 px-6 py-2 bg-orange-500 text-white rounded-full font-semibold hover:bg-orange-600 transition shadow-md"
              onClick={handleAddToCart}
            >
              Add to cart
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Modal;
