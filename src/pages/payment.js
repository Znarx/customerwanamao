import React, { useState } from "react";
import { useCart } from "/CartContext"; 
import { useRouter } from "next/router";

export default function Billing() {
  const { cartItems, clearCart } = useCart();
  const [paymentMethod, setPaymentMethod] = useState("Gcash");
  const [customerName, setCustomerName] = useState("");
  const [customerAddress, setCustomerAddress] = useState("");
  const [customerPhone, setCustomerPhone] = useState("");
  const router = useRouter();

  const total = cartItems.reduce((sum, item) => sum + (item.price * item.quantity || 0), 0);

  const handlePayment = () => {
    clearCart();
    router.push({
      pathname: "/confirmation",
      query: { 
        customerName, 
        customerAddress, 
        customerPhone, 
        total: total.toFixed(2),
        cartItems: JSON.stringify(cartItems)
      },
    }); 
  };

  return (
    <div className="min-h-screen bg-gray-100 flex justify-center items-center">
      <div className="w-full max-w-4xl bg-white rounded-lg shadow-lg p-8">
        <h1 className="text-4xl font-bold text-center text-gray-800 mb-6">Checkout</h1>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">

          {/* Customer Information */}
          <div className="border p-6 rounded-lg shadow-sm bg-gray-50">
            <h2 className="text-2xl font-semibold text-gray-700 mb-4">Delivery Information</h2>
            <div className="flex flex-col space-y-4">
              <div className="relative">
                <input 
                  type="text" 
                  value={customerName} 
                  onChange={(e) => setCustomerName(e.target.value)} 
                  placeholder="Full Name" 
                  className="p-3 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-red-500 w-full"
                  required
                />
                
              </div>
              <div className="relative">
                <input 
                  type="text" 
                  value={customerAddress} 
                  onChange={(e) => setCustomerAddress(e.target.value)} 
                  placeholder="Delivery Address" 
                  className="p-3 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-red-500 w-full"
                  required
                />
                
              </div>
              <div className="relative">
                <input 
                  type="tel" 
                  value={customerPhone} 
                  onChange={(e) => setCustomerPhone(e.target.value)} 
                  placeholder="Phone Number" 
                  className="p-3 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-red-500 w-full"
                  required
                />
                
              </div>
            </div>
          </div>

          {/* Order Summary */}
          <div className="border p-6 rounded-lg shadow-sm bg-gray-50">
            <h2 className="text-2xl font-semibold text-gray-700 mb-4">Order Summary</h2>
            <ul className="space-y-2">
              {cartItems.map((item) => (
                <li key={item.id} className="flex justify-between text-gray-600">
                  <span>{item.name} x{item.quantity}</span>
                  <span>₱{(item.price * item.quantity).toFixed(2)}</span>
                </li>
              ))}
            </ul>
            <div className="mt-4 text-lg font-bold text-gray-800">Total: ₱{total.toFixed(2)}</div>
          </div>

        </div>

        {/* Payment Method Selection */}
        <div className="mt-6 border-t border-gray-300 pt-4">
          <h2 className="text-2xl font-semibold text-gray-700 mb-2">Payment Method</h2>
          <div className="flex flex-col md:flex-row md:space-x-6">
            <label className="flex items-center mb-4">
              <input
                type="radio"
                id="cod"
                name="paymentMethod"
                value="COD"
                checked={paymentMethod === "COD"}
                onChange={() => setPaymentMethod("COD")}
                className="mr-2"
              />
              <span className="text-gray-600">Cash on Delivery</span>
            </label>
            <label className="flex items-center mb-4">
              <input
                type="radio"
                id="gcash"
                name="paymentMethod"
                value="Gcash"
                checked={paymentMethod === "Gcash"}
                onChange={() => setPaymentMethod("Gcash")}
                className="mr-2"
              />
              <span className="text-gray-600">Gcash</span>
            </label>
          </div>
        </div>

        {/* Confirm Payment Button */}
        <button
          onClick={handlePayment}
          className="w-full bg-red-500 text-white py-3 rounded-md shadow-md hover:bg-red-600 transition duration-200 text-lg font-semibold mt-6"
        >
          Confirm Payment
        </button>
      </div>
    </div>
  );
}
