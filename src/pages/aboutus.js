import Image from "next/image";
import Head from "next/head";
import Link from "next/link";
import { FaPhoneAlt } from "react-icons/fa";
import { FaFacebook } from "react-icons/fa";
import { FaTwitter } from "react-icons/fa";
import { FaInstagram } from "react-icons/fa";


const Aboutus = () => {
  return (
    <div>
      <Head>
        <title>About Us Page</title>
      </Head>

      {/* Navbar Section */}
      <div className="w-full max-w-1xl mx-auto flex items-center justify-between border-b-2 px-2 py-7 h-16 bg-black shadow-md">
        <div className="flex items-center space-x-8">
          <Image
            src="/Vector.png"
            alt="Lechon Logo"
            width={40}
            height={35}
            className="object-contain"
          />
        </div>
        <div className="flex-grow flex justify-center">
          <div className="flex space-x-6">
            <Link href="/">
              <button className="text-white hover:text-orange-500 transition bg-transparent border-none cursor-pointer">
                Home
              </button>
            </Link>
            <Link href="/letchon">
              <button className="text-white hover:text-orange-500 transition bg-transparent border-none cursor-pointer">
                Lechon
              </button>
            </Link>
            <Link href="/viands">
              <button className="text-white hover:text-orange-500 transition bg-transparent border-none cursor-pointer">
                Viands
              </button>
            </Link>
            <Link href="/packages">
              <button className="text-white hover:text-orange-500 transition bg-transparent border-none cursor-pointer">
                Packages
              </button>
            </Link>
            <Link href="/aboutus">
              <button className="text-white hover:text-orange-500 transition bg-transparent border-none cursor-pointer">
                About Us
              </button>
            </Link>
          </div>
        </div>

        <div className="flex items-center space-x-8">
          <Link href="/profile">
            <button className="flex items-center justify-center p-2 bg-transparent hover:bg-gray-800 rounded">
              <Image
                src="/profile.png"
                alt="Profile"
                width={24}
                height={24}
                className="cursor-pointer"
              />
            </button>
          </Link>
          <Link href="/cart">
            <button className="flex items-center justify-center p-2 bg-transparent hover:bg-gray-800 rounded">
              <Image
                src="/cart.png"
                alt="Cart"
                width={24}
                height={24}
                className="cursor-pointer"
              />
            </button>
          </Link>
        </div>
      </div>

      {/* About Us Section */}
      
      <div className="relative bg-yellow-100 text-center py-16">
        <div
          className="absolute inset-0 bg-cover bg-no-repeat opacity-10"
          style={{ backgroundImage: "url('/bg2.png')" }}
        ></div>
        <h1 className="text-4xl font-bold text-black mb-6">About Us</h1>
        <p className="text-xl text-black px-6 max-w-4xl mx-auto">
          Welcome to our culinary haven, where passion meets plate in a symphony
          of flavors and aromas. At Ruby Belly and Lechon, we are more than just
          purveyors of food; we are storytellers, weaving tales of tradition and
          innovation through every dish we craft. With a deep-rooted commitment
          to quality ingredients and culinary excellence.
        </p>
      </div>

      {/* Contact Us Section */}
      <div className="flex flex-col md:flex-row items-center bg-orange-200 py-10 px-6">
        <div className="flex-1 text-left">
          <h2 className="text-2xl font-bold mb-4">Contact Us</h2>
          <p className="text-lg mb-2 flex items-center">
            <FaPhoneAlt className="mr-2" />
            (+63) 09513785774
          </p>
          <p className="text-lg flex items-center">
            <FaFacebook className="mr-2" />
            Ruby Belly and Lechon
          </p>
        </div>
        <div className="flex-1 mt-6 md:mt-0">
          <Image
            src="/letchon.png"
            alt="Lechon Image"
            width={500}
            height={350}
            className="object-cover rounded-lg"
          />
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
};

export default Aboutus;
