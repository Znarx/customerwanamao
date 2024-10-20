import Image from "next/image";
import Head from "next/head";
import { useRouter } from "next/router";
import React from "react";
import { FaFacebook, FaTwitter, FaInstagram } from "react-icons/fa";

export default function Home() {
  const router = useRouter(); // Initialize the router

  const handleOrderNowClick = () => {
    router.push("/login"); // Redirect to login page when "Order Now" is clicked
  };

  return (
    <div>
      <Head>
        <title>Home Page</title>
        <meta name="description" content="Order delicious lechon and viands from Ruby Belly & Lechon" />
        <link rel="icon" href="/favicon.ico" />
      </Head>

      {/* Header */}
      <div className="w-full max-w-1xl mx-auto flex items-center justify-between border-b-2 px-2 py-7 h-16 bg-black shadow-md">
        <div className="flex items-center space-x-8">
          <Image
            src="/Vector.png"
            alt="Lechon Logo"
            width={40}
            height={35}
            priority
            className="object-contain"
          />
        </div>
        <div className="flex-grow flex justify-center">
          <div className="flex space-x-6">
            <button onClick={() => router.push("/")} className="text-white font-bold hover:text-orange-500 transition">
              Home
            </button>
            <button onClick={() => router.push("/letchon")} className="text-white font-bold hover:text-orange-500 transition">
              Lechon
            </button>
            <button onClick={() => router.push("/viands")} className="text-white font-bold hover:text-orange-500 transition">
              Viands
            </button>
            <button onClick={() => router.push("/packages")} className="text-white font-bold hover:text-orange-500 transition">
              Packages
            </button>
            <button onClick={() => router.push("/aboutus")} className="text-white font-bold hover:text-orange-500 transition">
              About Us
            </button>
          </div>
        </div>
        <div className="flex items-center space-x-8">
          <button onClick={() => router.push("/profile")} aria-label="Profile Page">
            <Image src="/profile.png" alt="Profile" width={24} height={24} className="cursor-pointer" />
          </button>
          <button onClick={() => router.push("/cart")} aria-label="Cart Page">
            <Image src="/cart.png" alt="Cart" width={24} height={24} className="cursor-pointer" />
          </button>
        </div>
      </div>

      {/* Hero Section */}
      <div className="relative w-full h-[50vh] md:h-[70vh] bg-cover bg-center" style={{ backgroundImage: "url('/belly.jpg')" }}>
        <div className="absolute inset-0 bg-black bg-opacity-30"></div>
        <div className="absolute inset-0 flex flex-col justify-center items-center">
          <h1 className="text-white text-4xl md:text-6xl font-bold mb-4">Ruby Belly & Lechon</h1>
          <button 
            onClick={handleOrderNowClick} 
            className="bg-red-600 text-white px-6 py-3 text-lg font-semibold rounded-md hover:bg-red-500 transition"
          >
            Order Now
          </button>
        </div>
      </div>

      {/* Viands Section */}
      <div className="bg-yellow-100 py-10">
        <div className="container mx-auto grid grid-cols-1 md:grid-cols-3 gap-6 px-4">
          {[
            {
              src: "https://chattrade.com/uploads/images/recipes/b281386e75160275fdbe614bc6c08ef7.jpg",
              name: "Lumpia",
            },
            {
              src: "https://img.freepik.com/premium-photo/rustic-fried-chicken-presentation_1179130-16613.jpg",
              name: "Fried Chicken",
            },
            {
              src: "https://recipes.net/wp-content/uploads/2023/12/how-to-cook-lechon-belly-in-oven-1701786912.jpg",
              name: "Lechon Belly",
            },
          ].map((item, idx) => (
            <div key={idx} className="bg-white p-4 shadow-lg hover:shadow-xl transition">
              <div className="w-full h-[300px] relative overflow-hidden">
                <Image
                  src={item.src}
                  alt={item.name}
                  layout="fill"
                  objectFit="cover"
                  className="rounded-lg"
                />
              </div>
              <p className="text-2xl font-bold mt-2 text-center">{item.name}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Footer */}
      <footer className="bg-black text-white py-6">
        <div className="container mx-auto flex justify-center space-x-8">
          <a
            href="https://twitter.com"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 hover:bg-gray-900 p-2 rounded-md group cursor-pointer hover:shadow-lg"
          >
            <FaTwitter className="text-2xl text-gray-600 group-hover:text-white" />
            <span className="ml-2 text-gray-600 group-hover:text-white">Twitter</span>
          </a>
          <a
            href="https://facebook.com"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 hover:bg-gray-900 p-2 rounded-md group cursor-pointer hover:shadow-lg"
          >
            <FaFacebook className="text-2xl text-gray-600 group-hover:text-white" />
            <span className="ml-2 text-gray-600 group-hover:text-white">Facebook</span>
          </a>
          <a
            href="https://instagram.com"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 hover:bg-gray-900 p-2 rounded-md group cursor-pointer hover:shadow-lg"
          >
            <FaInstagram className="text-2xl text-gray-600 group-hover:text-white" />
            <span className="ml-2 text-gray-600 group-hover:text-white">Instagram</span>
          </a>
        </div>
      </footer>
    </div>
  );
}
