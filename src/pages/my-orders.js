import React, { useEffect, useState } from "react";
import Head from "next/head";

const MyOrders = () => {
  const [orders, setOrders] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Fetch orders from the API when the component mounts
  useEffect(() => {
    const fetchOrders = async () => {
      try {
        const response = await fetch("/api/orders"); // Adjust to your API endpoint
        if (!response.ok) {
          throw new Error("Failed to fetch orders");
        }
        const data = await response.json();
        setOrders(data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchOrders();
  }, []);

  // Filter orders to show only those that are 'Processing'
  const processingOrders = orders.filter(order => order.status === "Processing");

  return (
    <div className="min-h-screen bg-gray-100 p-10">
      <Head>
        <title>My Orders</title>
      </Head>
      <div className="max-w-4xl mx-auto bg-white p-8 shadow-md rounded-lg">
        <h1 className="text-3xl font-bold mb-6">My Orders</h1>

        {loading ? (
          <p className="text-gray-600">Loading orders...</p> // Change loading message
        ) : error ? (
          <p className="text-red-500">Error: {error}</p>
        ) : processingOrders.length > 0 ? (
          <div className="space-y-4">
            {processingOrders.map((order) => (
              <div key={order.id} className="bg-gray-50 p-4 rounded-md shadow-md">
                <p className="text-lg font-bold">Order ID: {order.id}</p>
                <p>Customer Name: {order.customer_name}</p> {/* Adjust as per your database field */}
                <p>Quantity: {order.quantity}</p>
                <p>Status: 
                  <span className="font-semibold text-yellow-500">{order.status}</span>
                </p>
                <p>Date: {new Date(order.date).toLocaleDateString()}</p> {/* Format date */}
              </div>
            ))}
          </div>
        ) : (
          <p className="text-gray-600">No orders are currently being processed.</p>
        )}
      </div>
    </div>
  );
};

export default MyOrders;
