import React, { useState } from "react";


const LetchonModal = ({ isVisible, onClose, children }) => {
    if (!isVisible) return null;
  
    const handleClose = (e) => {
      if (e.target.id === 'wrapper') onClose();
    };
  
    return (
      <div
        className="fixed inset-0 bg-black bg-opacity-25 backdrop-blur-sm flex justify-center items-center"
        id="wrapper"
        onClick={handleClose}
      >
        <div className="w-[600px] flex flex-col">
          <button className="text-red-100 text-xl place-self-end hover:orange-500" onClick={onClose}>
            X
          </button>
          <div className="bg-white p-2 rounded">{children}</div>
        </div>
      </div>
    );
  };
  
  export default LetchonModal;
  