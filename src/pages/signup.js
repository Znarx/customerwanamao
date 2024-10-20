import React, { useState } from "react";
import Image from "next/image";
import Head from "next/head";
import Link from "next/link";
import { HiEye, HiEyeOff } from "react-icons/hi";
import axios from 'axios';

export default function Signup() {
  
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [fullname, setFullname] = useState('');
  const [phoneNumber, setPhoneNumber] = useState('');
  const [emailaddress, setEmailAddress] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const togglePasswordVisibility = () => {
    setShowPassword(!showPassword);
  };

  const toggleConfirmPasswordVisibility = () => {
    setShowConfirmPassword(!showConfirmPassword);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (password !== confirmPassword) {
      alert("Passwords do not match");
      return;
    }

    try {
      const response = await axios.post('/api/signup', {
        fullname,
        phoneNumber,
        emailaddress,
        password
      });

      if (response.data.success) {
        alert("Signup successful. Please login.");
        // Redirect to login page or perform any other necessary actions
      } else {
        alert("Signup failed. Please try again.");
      }
    } catch (error) {
      console.error("Error during signup:", error);
      alert("An error occurred during signup. Please try again later.");
    }
  };

  return (
    <div
      className="flex flex-col items-center justify-center min-h-screen py-2 bg-gray-100"
      style={{
        backgroundImage: 'url(/Login.png)',
        backgroundSize: 'cover',
        backgroundPosition: 'center',
        backgroundRepeat: 'no-repeat',
        backgroundAttachment: 'fixed',
      }}
    >
      <Head>
        <title>Signup</title>
        <link rel="icon" href="../public/favicon.ico" />
      </Head>

      <main className="flex flex-col justify-center items-center w-full flex-1 px-20 text-center">
        <div className="bg-orange-900 text-white rounded-2xl shadow-2xl border-2 border-black flex w-full max-w-4xl h-[40rem] relative">
          <div className="w-1/2 h-full bg-orange-700 rounded-2xl shadow-md p-10">
            <h2 className="text-2xl font-bold text-white mb-1">Signup</h2>
            <div className="border-2 w-10 border-white inline-block mb-4"></div>

            <form onSubmit={handleSubmit} className="flex flex-col space-y-4">
              <div>
                <label htmlFor="fullname" className="text-white block text-left mb-1">
                  Fullname
                </label>
                <input
                  type="text"
                  id="fullname"
                  name="fullname"
                  value={fullname}
                  onChange={(e) => setFullname(e.target.value)}
                  className="w-full p-2 rounded-lg border border-gray-300 text-black focus:outline-none focus:ring-2 focus:ring-orange-500"
                  placeholder="Fullname"
                  required
                />
              </div>

              <div>
                <label htmlFor="phone-number" className="text-white block text-left mb-1">
                  Phone Number
                </label>
                <input
                  type="text"
                  id="phone-number"
                  name="phone-number"
                  value={phoneNumber}
                  onChange={(e) => setPhoneNumber(e.target.value)}
                  className="w-full p-2 rounded-lg border border-gray-300 text-black focus:outline-none focus:ring-2 focus:ring-orange-500"
                  placeholder="Phone Number"
                  required
                />
              </div>

              <div>
                <label htmlFor="email" className="text-white block text-left mb-1">
                  Email Address
                </label>
                <input
                  type="email"
                  id="email"
                  name="email"
                  value={emailaddress}
                  onChange={(e) => setEmailAddress(e.target.value)}
                  className="w-full p-2 rounded-lg border border-gray-300 text-black focus:outline-none focus:ring-2 focus:ring-orange-500"
                  placeholder="Enter your email"
                  required
                />
              </div>

              {/* Password Field with Toggle */}
              <div className="relative">
                <label htmlFor="password" className="text-white block text-left mb-1">
                  Password
                </label>
                <div className="flex items-center bg-gray-200 rounded-md p-2">
                  <input
                    type={showPassword ? "text" : "password"}
                    id="password"
                    name="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Password"
                    className="w-full bg-transparent outline-none text-black placeholder-gray-500"
                    required
                  />
                  <button
                    type="button"
                    onClick={togglePasswordVisibility}
                    className="absolute right-2 text-gray-500"
                    aria-label={showPassword ? "Hide password" : "Show password"}
                  >
                    {showPassword ? <HiEyeOff className="w-5 h-5" /> : <HiEye className="w-5 h-5" />}
                  </button>
                </div>
              </div>

              {/* Confirm Password Field with Toggle */}
              <div className="relative">
                <label htmlFor="confirm-password" className="text-white block text-left mb-1">
                  Confirm Password
                </label>
                <div className="flex items-center bg-gray-200 rounded-md p-2">
                  <input
                    type={showConfirmPassword ? "text" : "password"}
                    id="confirm-password"
                    name="confirm-password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="Confirm Password"
                    className="w-full bg-transparent outline-none text-black placeholder-gray-500"
                    required
                  />
                  <button
                    type="button"
                    onClick={toggleConfirmPasswordVisibility}
                    className="absolute right-2 text-gray-500"
                    aria-label={showConfirmPassword ? "Hide password" : "Show password"}
                  >
                    {showConfirmPassword ? <HiEyeOff className="w-5 h-5" /> : <HiEye className="w-5 h-5" />}
                  </button>
                </div>
              </div>

              <button
                type="submit"
                className="bg-white text-orange-700 font-semibold rounded-full px-4 py-3 mt-4 hover:bg-orange-500 hover:text-white transition"
              >
                Submit
              </button>
            </form>
          </div>

          <div className="w-1/2 flex flex-col justify-center items-center">
            <Link href="/">
              <button className="flex items-center justify-center p-2 bg-transparent hover:bg-gray-800 rounded">
                <Image
                  src="/Vector.png"
                  alt="Profile"
                  width={24}
                  height={24}
                  className="cursor-pointer"
                />
              </button>
            </Link>
            <h2 className="text-5xl font-bold mb-5">WELCOME!</h2>
            <div className="border-2 w-10 border-white inline-block mb-20"></div>
            <p className="mb-4">Already Have an Account?</p>
            <Link href="/login">
              <button className="border-2 border-white rounded-full px-12 py-2 font-semibold hover:bg-white hover:text-red-500 transition">
                Login
              </button>
            </Link>
          </div>
        </div>
      </main>
    </div>
  );
}