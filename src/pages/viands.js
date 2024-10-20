import React, { Fragment, useState } from "react";
import Image from "next/image";
import Head from "next/head";
import Link from "next/link";
import { FaFacebook, FaTwitter, FaInstagram } from "react-icons/fa";
import { useCart } from "/CartContext"; 
import Modal from "../components/cartModal"; 

const Viands = () => {
  const [selectedViand, setSelectedViand] = useState(null);
  const [showModal, setShowModal] = useState(false);
  const { addToCart } = useCart();

  const handleViandClick = (viand) => {
    setSelectedViand(viand);
    setShowModal(true);
  };

  
  const handleAddToCart = (viand) => {
    // Add viand to cart logic
    
  };

  const closeModal = () => {
    setShowModal(false);
    setSelectedViand(null);
  };

  

  return (
    <Fragment>
      <div>
        <Head>
          <title>Viands Page</title>
        </Head>
        <div className="w-full max-w-full mx-auto flex items-center justify-between border-b-2 px-2 py-7 h-16 bg-black shadow-md">
          <div className="flex items-center space-x-8">
            <Image src="/Vector.png" alt="Letchon Logo" width={40} height={35} className="object-contain" />
          </div>
          <div className="flex-grow flex justify-center">
            <div className="flex space-x-6">
              <Link href="/"><button className="text-white hover:text-orange-500">Home</button></Link>
              <Link href="/letchon"><button className="text-white hover:text-orange-500">Lechon</button></Link>
              <Link href="/viands"><button className="text-white hover:text-orange-500">Viands</button></Link>
              <Link href="/packages"><button className="text-white hover:text-orange-500">Packages</button></Link>
              <Link href="/aboutus"><button className="text-white hover:text-orange-500">About Us</button></Link>
            </div>
          </div>
          <div className="flex items-center space-x-8">
            <Link href="/profile"><button className="flex items-center justify-center p-2"><Image src="/profile.png" alt="Profile" width={24} height={24} /></button></Link>
            <Link href="/cart"><button className="flex items-center justify-center p-2"><Image src="/cart.png" alt="Cart" width={24} height={24} /></button></Link>
          </div>
        </div>

        <div className="flex flex-col items-center justify-center py-10" style={{ backgroundColor: '#F8C794' }}>
          <main className="flex flex-col justify-center items-center w-full flex-1 px-4 text-center">
            <h1 className="text-5xl font-bold mb-6 text-orange-700 drop-shadow-lg">Viands</h1>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-8">
              {viandsData.map((viand, index) => (
                <div
                key={index}
                className="bg-white shadow-lg rounded-lg p-4 cursor-pointer hover:shadow-2xl hover:scale-105 transform transition-all duration-300 ease-in-out"
                onClick={() => handleViandClick(viand)}
              >
                  <Image 
                    src={viand.imageSrc} 
                    alt={viand.name} 
                    width={300} 
                    height={200} 
                    className="object-cover rounded-lg h-64 w-full mb-2" 
                    style={{ objectFit: "cover" }} 
                  />
                  <h3 className="text-lg font-semibold mt-2 text-gray-800">{viand.name}</h3>
                  <p className="text-lg font-bold text-gray-800">₱{viand.price}</p>
                  
                  <button
                    className="bg-orange-500 text-white py-2 px-4 rounded hover:bg-orange-600"
                  onClick={() => handleAddToCart({ name: 'Fried Chicken' })}
                >
               Add to Cart
                </button>
                </div>
              ))}
            </div>
          </main>
        </div>

        <Modal 
          showModal={showModal} 
          selectedViand={selectedViand} 
          closeModal={closeModal} 
          addToCart={addToCart} 
        />

        


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
    </Fragment>
  );
};


const viandsData = [
  {
    id: 1,
    name: "Lumpiang Shanghai",
    price: 300,
    imageSrc: "https://chattrade.com/uploads/images/recipes/b281386e75160275fdbe614bc6c08ef7.jpg",
    description: "Crispy spring rolls filled with a mix of ground pork and vegetables.",
    servings: 4, // Number of people it can serve
  },
  {
    id: 2,
    name: "Fried Chicken",
    price: 600,
    imageSrc: "https://img.freepik.com/premium-photo/rustic-fried-chicken-presentation_1179130-16613.jpg",
    description: "Golden fried chicken wings, seasoned to perfection.",
    servings: 6,
  },
  {
    id: 3,
    name: "Sweet & Sour Fish",
    price: 500,
    imageSrc: "https://crabsdelivery.com.sg/wp-content/uploads/2020/11/sweet-and-sour-fish.jpg",
    description: "Tender fish fillets served in a sweet and tangy sauce.",
    servings: 4,
  },
  {
    id: 4,
    name: "Chicken Curry",
    price: 800,
    imageSrc: "https://images.getrecipekit.com/v1623822425_Chicken_Curry_n8jmnr.jpg?aspect_ratio=16:9&quality=90&auto_optimize=medium",
    description: "Rich and creamy chicken curry with a hint of spice.",
    servings: 5,
  },
  {
    id: 5,
    name: "Pork Adobo",
    price: 800,
    imageSrc: "https://salu-salo.com/wp-content/uploads/2015/04/Pork-Adobo-3.jpg",
    description: "Chicken adobo, also known as adobong manok, is a quintessential Filipino braised chicken, marinated and stewed with vinegar, soy sauce, garlic, bay leaves, black peppercorns.",
    servings: 6,
  },
  {
    id: 6,
    name: "Buttered Shrimp",
    price: 500,
    imageSrc: "https://www.jocooks.com/wp-content/uploads/2021/09/garlic-butter-shrimp-1-10-750x750.jpg",
    description: "Succulent shrimp sautéed in butter and garlic.",
    servings: 3,
  },
  {
    id: 7,
    name: "Pork Afritada",
    price: 600,
    imageSrc: "https://www.thepeachkitchen.com/wp-content/uploads/2021/08/Pork-Afritada2.png",
    description: "Pork stew cooked with tomatoes, potatoes, and carrots.",
    servings: 4,
  },
  {
    id: 8,
    name: "Pancit Guisado",
    price: 400,
    imageSrc: "https://graceland.ph/wp-content/uploads/2023/05/PANCIT-GUISADO-SALO.jpg",
    description: "Stir-fried noodles with vegetables, pork, and shrimp.",
    servings: 5,
  },
];

export default Viands;
