import Image from "next/image";
import Link from "next/link";
import { FaFacebook, FaTwitter, FaInstagram, FaPlusCircle } from "react-icons/fa";
import Modal from "../components/letchonModal"; 
import { Fragment, useState } from "react";
import { useCart } from "/CartContext"; 


    const Letchon = () => {
    const [showModal, setShowModal] = useState(false);
    const [showModal2, setShowModal2] = useState(false);
    const { addToCart } = useCart(); 

    const handleOrder = (item) => {
        addToCart({
        id: item.id,       
        name: item.name,   
        price: item.price, 
        quantity: 1,       
        imageSrc: item.imageSrc 
        });

        if (item.name === "Lechon Belly") {
        setShowModal(false);
        } else {
        setShowModal2(false);
        }
    };

    return (
        <Fragment>
        <div>
        
        <div className="w-full max-w-1xl mx-auto flex items-center justify-between border-b-2 px-2 py-7 h-16 bg-black shadow-md">
            <div className="flex items-center space-x-8">
            <Image
                src="/Vector.png"
                alt="Letchon Logo"
                width={40}
                height={35}
                className="object-contain"
            />
            </div>
            <div className="flex-grow flex justify-center">
            <div className="flex space-x-6">
                <Link href="/">
                <button className="text-white font-bold hover:text-orange-500 transition bg-transparent border-none cursor-pointer">
                    Home
                </button>
                </Link>
                <Link href="/letchon">
                <button className="text-white font-bold hover:text-orange-500 transition bg-transparent border-none cursor-pointer">
                    Lechon
                </button>
                </Link>
                <Link href="/viands">
                <button className="text-white font-bold hover:text-orange-500 transition bg-transparent border-none cursor-pointer">
                    Viands
                </button>
                </Link>
                <Link href="/packages">
                <button className="text-white font-bold hover:text-orange-500 transition bg-transparent border-none cursor-pointer">
                    Packages
                </button>
                </Link>
                <Link href="/aboutus">
                <button className="text-white font-bold hover:text-orange-500 transition bg-transparent border-none cursor-pointer">
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

        
        <div className="relative bg-[#f7c18e] w-full h-[85vh] flex items-center justify-center">
            
            <div className="absolute inset-0">
            <Image
                src="/hehe.png" 
                alt="Lechon Background"
                fill
                className="object-cover"
            />
            </div>
            <div className="relative flex flex-col md:flex-row items-center justify-around w-full px-4 py-6">
            
            <div className="relative bg-[#ff6b35] text-white rounded-lg shadow-lg p-6 md:p-10 mb-6 md:mb-0 md:w-[45%] translate-y-8">
                <button className="absolute top-0 right-0 transform translate-x-4 -translate-y-4"
                onClick={() => setShowModal(true)}>
                <Image
                    src="https://partybashcatering.com/wp-content/uploads/2021/06/lechon-2.jpg"
                    alt="Lechon Belly Icon"
                    width={200}
                    height={200} 
                    className="rounded-full border-4 border-white"
                />
                </button>
                <div className="ml-56 mt-8 flex items-center space-x-4"> 
                <h2 className="text-3xl font-bold mb-4">Lechon Belly</h2>
                <button className=" absolute top-0 right-0 transform translate-x-4 -translate-y-4 p-2 bg-gray-500 text-white rounded-full shadow-md hover:bg-orange-600 focus:outline-none" 
                onClick={() => setShowModal(true)}>
                    <FaPlusCircle className="text-xl " />
                </button>
                </div>
            </div>

            
            <div className="left-8 relative bg-[#ff6b35] text-white rounded-lg shadow-lg p-6 md:p-10 md:mb-0 md:w-[45%] -translate-y-8">
                <button className="absolute top-0 left-0 transform -translate-x-4 -translate-y-4"
                onClick={() => setShowModal2(true)}>
                <Image
                    src="/leytchon.png"
                    alt="Lechon Baboy Icon"
                    width={200}
                    height={200} 
                    className="rounded-full border-4 border-white"
                />
                </button>
                <div className="ml-56 mt-8 flex items-center space-x-4"> 
                <h2 className="text-4xl font-bold mb-4">Lechon Baboy</h2>
                <button className=" absolute top-0 left-0 transform -translate-x-4 -translate-y-4 p-2 bg-gray-500 text-white rounded-full shadow-md hover:bg-orange-600 focus:outline-none"
                onClick={() => setShowModal2(true)}>

                    <FaPlusCircle className="text-xl " />
                </button>
                </div>
                
            </div>
            </div>
        </div>

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
        <Modal isVisible={showModal} onClose={() => setShowModal(false)}>
            <div className="p-8 bg-gray-300 rounded-lg shadow-xl relative">
            <h3 className="text-2xl font-bold text-gray-800 mb-6 text-center">Lechon Belly</h3>
            <h3 className="text-1xl font-bold text-gray-800 mb-6 text-center">Price List</h3>

            {/* Price List */}
            <div className="flex flex-col items-center p-2 bg-gray-200">
                <table className=" table-auto border-collapse w-full text-left text-gray-700 rounded-lg overflow-hidden shadow-md">
                <thead>
                    <tr className="bg-gradient-to-r from-orange-400 to-orange-600 text-white">
                    <th className="py-3 px-6 border-b">Kilos</th>
                    <th className="py-3 px-6 border-b">Price</th>
                    <th className="py-3 px-6 border-b">Order</th>
                    </tr>
                </thead>
                <tbody>
                    <tr className="hover:bg-orange-50 transition duration-200">
                    <td className="py-3 px-6 border-b">3 kls</td>
                    <td className="py-3 px-6 border-b">₱1,800</td>
                    <td className="py-3 px-6 border-b text-center">
                    <button
                        className="bg-orange-500 hover:bg-[#f7c18e] text-white font-bold py-2 px-4 rounded-lg transition-all duration-200"
                        onClick={() =>
                        handleOrder({
                            id: 1,
                            name: "Lechon Belly",
                            price: 1800,
                            imageSrc: "/belly.jpg",
                        })
                        }
                    >
                        Order
                    </button>
                    </td>
                </tr>
                    <tr className="hover:bg-orange-50 transition duration-200">
                    <td className="py-3 px-6 border-b">4 kls</td>
                    <td className="py-3 px-6 border-b">₱2,200</td>
                    <td className="py-3 px-6 border-b text-center">
                    <button
                        className="bg-orange-500 hover:bg-[#f7c18e] text-white font-bold py-2 px-4 rounded-lg transition-all duration-200"
                        onClick={() =>
                        handleOrder({
                            id: 2,
                            name: "Lechon Belly",
                            price: 2200,
                            imageSrc: "/belly.jpg",
                        })
                        }
                    >
                        Order
                    </button>
                    </td>
                </tr>
                    <tr className="hover:bg-orange-50 transition duration-200">
                    <td className="py-3 px-6 border-b">5 kls</td>
                    <td className="py-3 px-6 border-b">₱2,600</td>
                    <td className="py-3 px-6 border-b text-center">
                    <button
                        className="bg-orange-500 hover:bg-[#f7c18e] text-white font-bold py-2 px-4 rounded-lg transition-all duration-200"
                        onClick={() =>
                        handleOrder({
                            id: 3,
                            name: "Lechon Belly",
                            price: 2600,
                            imageSrc: "/belly.jpg",
                        })
                        }
                    >
                        Order
                    </button>
                    </td>
                </tr>
                    <tr className="hover:bg-orange-50 transition duration-200">
                    <td className="py-3 px-6 border-b">6 kls</td>
                    <td className="py-3 px-6 border-b">₱2,900</td>
                    <td className="py-3 px-6 border-b text-center">
                    <button
                        className="bg-orange-500 hover:bg-[#f7c18e] text-white font-bold py-2 px-4 rounded-lg transition-all duration-200"
                        onClick={() =>
                        handleOrder({
                            id: 4,
                            name: "Lechon Belly",
                            price: 2900,
                            imageSrc: "/belly.jpg",
                        })
                        }
                    >
                        Order
                    </button>
                    </td>
                </tr>
                </tbody>
                </table>
            </div>
            </div>
        </Modal>


        <Modal isVisible={showModal2} onClose={() => setShowModal2(false)}>
            <div className="p-8 bg-gray-300 rounded-lg shadow-xl relative">
            <h3 className="text-2xl font-bold text-gray-800 mb-6 text-center">Lechon Baboy</h3>
            <h3 className="text-1xl font-bold text-gray-800 mb-6 text-center">Price List</h3>

            {/* Price List */}
            <div className="flex flex-col items-center p-2 bg-gray-200">
                <table className=" table-auto border-collapse w-full text-left text-gray-700 rounded-lg overflow-hidden shadow-md">
                <thead>
                    <tr className="bg-gradient-to-r from-orange-400 to-orange-600 text-white">
                    <th className="py-3 px-6 border-b">Pax</th>
                    <th className="py-3 px-6 border-b">Kilos</th>
                    <th className="py-3 px-6 border-b">Price</th>
                    <th className="py-3 px-6 border-b">Order</th>
                    </tr>
                </thead>
                <tbody>
                    <tr className="hover:bg-orange-50 transition duration-200">
                    <td className="py-3 px-6 border-b">10-12</td>
                    <td className="py-3 px-6 border-b">12-15 kls</td>
                    <td className="py-3 px-6 border-b">₱4000</td>
                    <td className="py-3 px-6 border-b text-center">
                        <button
                        className="bg-orange-500 hover:bg-[#f7c18e] text-white font-bold py-2 px-4 rounded-lg transition-all duration-200"
                        onClick={() =>
                        handleOrder({
                            id: 5,
                            name: "Lechon Baboy",
                            price: 4000,
                            imageSrc: "/leytchon.png",
                        })
                        }
                    >
                        Order
                    </button>
                    </td>
                    </tr>
                    <tr className="hover:bg-orange-50 transition duration-200">
                    <td className="py-3 px-6 border-b">15-18</td>
                    <td className="py-3 px-6 border-b">15-19 kls</td>
                    <td className="py-3 px-6 border-b">₱4500</td>
                    <td className="py-3 px-6 border-b text-center">
                    <button
                        className="bg-orange-500 hover:bg-[#f7c18e] text-white font-bold py-2 px-4 rounded-lg transition-all duration-200"
                        onClick={() =>
                        handleOrder({
                            id: 6,
                            name: "Lechon Baboy",
                            price: 4500,
                            imageSrc: "/leytchon.png",
                        })
                        }
                    >
                        Order
                    </button>
                    </td>
                    </tr>
                    <tr className="hover:bg-orange-50 transition duration-200">
                    <td className="py-3 px-6 border-b">25-30</td>
                    <td className="py-3 px-6 border-b">20-22 kls</td>
                    <td className="py-3 px-6 border-b">₱5000</td>
                    <td className="py-3 px-6 border-b text-center">
                    <button
                        className="bg-orange-500 hover:bg-[#f7c18e] text-white font-bold py-2 px-4 rounded-lg transition-all duration-200"
                        onClick={() =>
                        handleOrder({
                            id: 7,
                            name: "Lechon Baboy",
                            price: 5000,
                            imageSrc: "/leytchon.png",
                        })
                        }
                    >
                        Order
                    </button>
                    </td>
                    </tr>           
                    <tr className="hover:bg-orange-50 transition duration-200">
                    <td className="py-3 px-6 border-b">40-45</td>
                    <td className="py-3 px-6 border-b">30-35 kls</td>
                    <td className="py-3 px-6 border-b">₱7000</td>
                    <td className="py-3 px-6 border-b text-center">
                    <button
                        className="bg-orange-500 hover:bg-[#f7c18e] text-white font-bold py-2 px-4 rounded-lg transition-all duration-200"
                        onClick={() =>
                        handleOrder({
                            id: 8,
                            name: "Lechon Baboy",
                            price: 7000,
                            imageSrc: "/leytchon.png",
                        })
                        }
                    >
                        Order
                    </button>
                    </td>
                    </tr>
                </tbody>
                </table>
            </div>
            </div>
        </Modal>
        </Fragment>
    );
    };

    export default Letchon;

        //https://t4.ftcdn.net/jpg/05/43/41/81/360_F_543418171_f4C48sKCsL9abYmhgSfRyVq4aQdhRGxA.jpg