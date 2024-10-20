import { useRouter } from "next/router";
import Link from "next/link";

export default function Confirmation() {
  const router = useRouter();
  const { customerName, customerAddress, customerPhone, total, cartItems } = router.query; // Destructure customer info from query
  const items = JSON.parse(cartItems || "[]"); // Parse cartItems back into an object

  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-[#F8C794] px-6 py-10">
      <h1 className="text-4xl font-bold mb-6 text-center">Thank You for Your Purchase!</h1>
      <p className="text-lg text-center mb-4">Your order has been successfully placed.</p>

      {/* Order Summary Section */}
      <div className="bg-white rounded-lg shadow-md p-6 mb-6 w-full max-w-lg">
        <h2 className="text-2xl font-semibold mb-4">Order Summary</h2>
        <ul className="space-y-3">
          {items.map((item) => (
            <li key={item.id} className="flex justify-between text-lg">
              <span>{item.name} x{item.quantity}</span>
              <span>₱{(item.price * item.quantity).toFixed(2)}</span>
            </li>
          ))}
        </ul>
        <div className="border-t border-gray-300 my-4"></div>
        <div className="mt-2 text-xl font-bold">
          Total Amount: <span className="text-red-600">₱{total}</span>
        </div>
      </div>

      {/* Customer Information Section */}
      <div className="bg-white rounded-lg shadow-md p-6 w-full max-w-lg">
        <h2 className="text-2xl font-semibold mb-4">Billing Information</h2>
        <p className="text-lg"><strong>Name:</strong> {customerName}</p>
        <p className="text-lg"><strong>Address:</strong> {customerAddress}</p>
        <p className="text-lg"><strong>Phone:</strong> {customerPhone}</p>
      </div>

      {/* Continue Shopping Button */}
      <Link href="/">
        <button className="bg-black text-white py-3 px-8 rounded-full shadow-md hover:bg-gray-800 transition duration-200 mt-8">
          Continue Shopping
        </button>
      </Link>
    </div>
  );
}
