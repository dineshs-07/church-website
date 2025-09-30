import React from "react";
import { FaFacebookF, FaInstagram, FaYoutube } from "react-icons/fa";

const Footer = () => {
  return (
    <footer className="bg-gradient-to-r from-blue-800 via-blue-900 to-indigo-900 text-white relative overflow-hidden py-12">
      {/* Floating shapes */}
      <div className="absolute top-0 left-0 w-48 h-48 bg-yellow-400 rounded-full mix-blend-multiply filter blur-3xl opacity-30 animate-float"></div>
      <div className="absolute bottom-0 right-0 w-72 h-72 bg-pink-500 rounded-full mix-blend-multiply filter blur-3xl opacity-30 animate-float" style={{ animationDelay: "2s" }}></div>

      <div className="container mx-auto px-6 relative z-10 text-center">
        <h2 className="text-2xl md:text-3xl font-bold mb-4 drop-shadow-lg">
          Connect with Us
        </h2>
        <div className="flex justify-center space-x-8 mb-6">
          <a
            href="https://facebook.com"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="Visit us on Facebook"
            className="bg-white text-blue-800 p-3 rounded-full shadow-2xl hover:scale-110 transform transition duration-300"
          >
            <FaFacebookF size={20} />
          </a>
          <a
            href="https://instagram.com"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="Visit us on Instagram"
            className="bg-white text-pink-500 p-3 rounded-full shadow-2xl hover:scale-110 transform transition duration-300"
          >
            <FaInstagram size={20} />
          </a>
          <a
            href="https://youtube.com"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="Visit us on YouTube"
            className="bg-white text-red-600 p-3 rounded-full shadow-2xl hover:scale-110 transform transition duration-300"
          >
            <FaYoutube size={20} />
          </a>
        </div>
        <p className="text-sm text-gray-200">
          &copy; {new Date().getFullYear()} Full Gospel Ministries Church. All rights reserved.
        </p>
      </div>
    </footer>
  );
};

export default Footer;
