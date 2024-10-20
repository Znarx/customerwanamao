import React, { useState } from "react";
import Head from "next/head";
import Image from "next/image";
import SideNavbar from "../components/sidenavbar";
import ProfileModal from "../components/profileModal"; // Import the ProfileModal component
import ConfirmationModal from "../components/confirmationModal"; // Import the ConfirmationModal component

const Profile = () => {
  const [showModal, setShowModal] = useState(false);
  const [profile, setProfile] = useState(null); // Initial state is null
  const [showDeleteModal, setShowDeleteModal] = useState(false); // State for delete confirmation modal

  const openModal = () => setShowModal(true);
  const closeModal = () => setShowModal(false);

  const handleAddAccount = (data) => {
    setProfile(data); // Update the profile state with the new data
  };

  // Function to delete the profile
  const handleDeleteAccount = () => {
    setProfile(null); // Set profile back to null, simulating account deletion
    closeDeleteModal(); // Close the delete confirmation modal
  };

  // Open and close functions for the delete confirmation modal
  const openDeleteModal = () => setShowDeleteModal(true);
  const closeDeleteModal = () => setShowDeleteModal(false);

  return (
    <div className="flex min-h-screen bg-gray-200">
      <SideNavbar />
      <div className="flex-1 p-10">
        <div className="max-w-2xl mx-auto bg-white rounded-lg shadow-lg p-8">
          {profile ? (
            <>
              {/* Profile Header */}
              <div className="flex items-center mb-6 space-x-4">
                <img
                  src="/prof.png"
                  alt="Profile"
                  className="w-24 h-24 rounded-full border-4 border-blue-500 shadow-lg"
                />
                <div>
                  <h1 className="text-3xl font-bold text-gray-800">{profile.name}</h1>
                  <button className="mt-2 bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 px-4 rounded transition duration-200">
                    Edit Profile
                  </button>
                </div>
              </div>

              {/* Contact Details Section */}
              <div className="bg-gray-100 p-6 rounded-lg shadow-md">
                <h2 className="text-2xl font-semibold text-gray-800 mb-4">Contact Information</h2>
                <div className="space-y-2 text-gray-700">
                  <p><strong>Phone:</strong> {profile.phone}</p>
                  <p><strong>Address:</strong> {profile.address}</p>
                </div>
                <div className="flex space-x-4 mt-6">
                  <button className="bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 px-4 rounded transition duration-200">
                    Edit Details
                  </button>
                  <button
                    onClick={openDeleteModal}
                    className="bg-red-600 hover:bg-red-700 text-white font-semibold py-2 px-4 rounded transition duration-200"
                  >
                    Delete Account
                  </button>
                </div>
              </div>
            </>
          ) : (
            // Empty Profile State
            <div className="w-full flex flex-col items-center bg-white p-6 rounded-lg shadow-md">
              <h2 className="text-2xl font-semibold text-gray-800 mb-4">No Profile Found</h2>
              <button
                onClick={openModal}
                className="mt-6 bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 px-4 rounded transition duration-200"
              >
                Add Account
              </button>
              
            </div>
          )}
        </div>

        {/* Modal for adding account */}
        <ProfileModal
          showModal={showModal}
          closeModal={closeModal}
          handleAddAccount={handleAddAccount}
        />

        {/* Delete Confirmation Modal */}
        <ConfirmationModal
          showModal={showDeleteModal}
          closeModal={closeDeleteModal}
          confirmAction={handleDeleteAccount}
          message="Are you sure you want to delete this account?"
        />
      </div>
    </div>
  );
};

export default Profile;
