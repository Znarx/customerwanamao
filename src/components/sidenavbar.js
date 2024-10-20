import Link from "next/link";
import React from "react";
import { Disclosure, DisclosureButton } from "@headlessui/react";
import { GiHamburgerMenu, GiPig } from "react-icons/gi";
import { FaHome, FaShoppingCart } from "react-icons/fa";
import { PiBowlFoodBold } from "react-icons/pi";
import { LuPackageOpen } from "react-icons/lu";
import { BiLogOut } from "react-icons/bi";
import { BsFillQuestionCircleFill } from "react-icons/bs";

function SideNavbar() {
  return (
    <div>
      <Disclosure as="nav">
        {/* Hamburger Menu for Mobile */}
        <DisclosureButton className="absolute top-4 right-4 inline-flex items-center peer justify-center rounded-md p-2 text-gray-800 hover:bg-gray-900 hover:text-white focus:outline-none focus:ring-2 focus:ring-inset focus:ring-white group">
          <GiHamburgerMenu className="block md:hidden h-6 w-6" aria-hidden="true" />
        </DisclosureButton>

        {/* Sidebar */}
        <div className="p-6 w-1/2 h-screen bg-white z-20 fixed top-0 -left-96 lg:left-0 lg:w-60 peer-focus:left-0 peer:transition ease-out delay-150 duration-200">
          <div className="flex flex-col justify-start items-center space-y-4">
            {/* Profile Section */}
            <h1 className="text-lg text-center cursor-pointer font-bold text-blue-900 border-b border-gray-100 pb-4 w-full">
              Profile
            </h1>

            {/* Navigation Links */}
            <div className="my-4 border-b border-gray-100 pb-4 w-full">
              <Link href="/">
                <button className="w-full flex justify-start items-center gap-4 pl-5 hover:bg-gray-900 p-2 rounded-md group cursor-pointer hover:shadow-lg">
                  <FaHome className="text-2xl text-gray-600 group-hover:text-white" />
                  <h3 className="text-base text-gray-800 group-hover:text-white font-semibold">Home</h3>
                </button>
              </Link>

              <Link href="/letchon">
                <button className="w-full flex justify-start items-center gap-4 pl-5 hover:bg-gray-900 p-2 rounded-md group cursor-pointer hover:shadow-lg">
                  <GiPig className="text-2xl text-gray-600 group-hover:text-white" />
                  <h3 className="text-base text-gray-800 group-hover:text-white font-semibold">Letchon</h3>
                </button>
              </Link>

              <Link href="/viands">
                <button className="w-full flex justify-start items-center gap-4 pl-5 hover:bg-gray-900 p-2 rounded-md group cursor-pointer hover:shadow-lg">
                  <PiBowlFoodBold className="text-2xl text-gray-600 group-hover:text-white" />
                  <h3 className="text-base text-gray-800 group-hover:text-white font-semibold">Viands</h3>
                </button>
              </Link>

              <Link href="/packages">
                <button className="w-full flex justify-start items-center gap-4 pl-5 hover:bg-gray-900 p-2 rounded-md group cursor-pointer hover:shadow-lg">
                  <LuPackageOpen className="text-2xl text-gray-600 group-hover:text-white" />
                  <h3 className="text-base text-gray-800 group-hover:text-white font-semibold">Packages</h3>
                </button>
              </Link>

              <Link href="/my-orders">
                <button className="w-full flex justify-start items-center gap-4 pl-5 hover:bg-gray-900 p-2 rounded-md group cursor-pointer hover:shadow-lg">
                  <FaShoppingCart className="text-2xl text-gray-600 group-hover:text-white" />
                  <h3 className="text-base text-gray-800 group-hover:text-white font-semibold">My Orders</h3>
                </button>
              </Link>

              <Link href="/aboutus">
                <button className="w-full flex justify-start items-center gap-4 pl-5 hover:bg-gray-900 p-2 rounded-md group cursor-pointer hover:shadow-lg">
                  <BsFillQuestionCircleFill className="text-2xl text-gray-600 group-hover:text-white" />
                  <h3 className="text-base text-gray-800 group-hover:text-white font-semibold">About Us</h3>
                </button>
              </Link>
            </div>

            {/* Logout Button */}
            <div className="w-full my-4">
              <button className="w-full flex justify-start items-center gap-4 pl-5 border border-gray-200 hover:bg-gray-900 p-2 rounded-md group cursor-pointer hover:shadow-lg">
                <BiLogOut className="text-2xl text-gray-600 group-hover:text-white" />
                <h3 className="text-base text-gray-800 group-hover:text-white font-semibold">Logout</h3>
              </button>
            </div>
          </div>
        </div>
      </Disclosure>
    </div>
  );
}

export default SideNavbar;
