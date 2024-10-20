import React, { useState } from "react";
import Image from "next/image";

const PackagesModal = ({ isVisible, onClose, selectedMenu, addToCart }) => {
  const [quantity, setQuantity] = useState(1); // State for quantity

  if (!isVisible || !selectedMenu) return null; // Only render if visible and selectedMenu exists

  const handleClose = (e) => {
    if (e.target.id === "wrapper") {
      onClose(); // Close the modal when clicking outside
    }
  };

  const increaseQuantity = () => setQuantity((prev) => prev + 1); // Increase quantity
  const decreaseQuantity = () => {
    if (quantity > 1) {
      setQuantity((prev) => prev - 1); // Decrease quantity but prevent going below 1
    }
  };

  const handleAddToCart = () => {
    addToCart({ ...selectedMenu, quantity }); // Pass both the selected menu and quantity to the cart
    onClose(); // Optionally close the modal after adding to cart
  };

  return (
    <div
      className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 backdrop-blur-sm"
      id="wrapper"
      onClick={handleClose}
    >
      <div className="bg-[#d1b38f] rounded-lg p-6 w-11/12 md:w-3/4 lg:w-2/3 xl:w-1/2 shadow-lg relative flex flex-col md:flex-row">
        {/* Close Button */}
        <button
          className="absolute top-4 right-4 text-black text-2xl font-bold"
          onClick={onClose}
        >
          X
        </button>

        {/* Modal Content */}
        <div className="md:w-1/2 flex justify-center items-center">
          <Image
            src={selectedMenu.imageSrc}
            alt={selectedMenu.name}
            width={300}
            height={300}
            className="object-cover rounded-lg"
          />
        </div>

        <div className="md:w-1/2 p-4 flex flex-col justify-between">
          <div>
            <h2 className="text-3xl font-bold mb-4">{selectedMenu.name}</h2>

            <h3 className="text-1xl font-semibold mb-2">Inclusions:</h3>

            {/* Description as bullet points */}
            <ul className="text-lg text-black mb-4 space-y-2 list-disc list-inside">
              {selectedMenu.details?.map((detail, index) => (
                <li key={index} className="text-base text-black-800">
                  {detail}
                </li>
              ))}
            </ul>
          </div>

          {/* Price, Quantity, and Add to Cart */}
          <div className="mt-6">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center bg-white rounded-lg border-2 border-black px-4 py-2">
                <p className="text-xl font-bold text-black">₱{selectedMenu.price}</p>
              </div>

              {/* Quantity Controls */}
              <div className="flex items-center border border-gray-300 rounded-md overflow-hidden">
                <button
                  onClick={decreaseQuantity}
                  className="px-3 py-1 text-white bg-red-500 hover:bg-red-600 transition duration-150"
                >
                  -
                </button>
                <span className="px-4 text-gray-800">{quantity}</span>
                <button
                  onClick={increaseQuantity}
                  className="px-3 py-1 text-white bg-green-500 hover:bg-green-600 transition duration-150"
                >
                  +
                </button>
              </div>
            </div>

            <button
              className="w-full bg-[#ff6d00] text-black py-2 px-6 rounded-lg hover:bg-[#ff9a3c] font-bold text-lg transition duration-200"
              onClick={handleAddToCart} // Use the handleAddToCart function
            >
              Add {quantity} to cart
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default PackagesModal;
