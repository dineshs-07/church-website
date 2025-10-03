import React, { useState } from "react";
import Logo from "../assets/image.jpg";
import LeftImage from "../assets/left.png";   // Transparent PNG
import RightImage from "../assets/right.png"; // Transparent PNG

const HeroWithNavbar = () => {
  const menuItems = ["Home","About","Services","Events","Gallery","Donate","Contact"];
  const [isOpen, setIsOpen] = useState(false);

  return (
    <header className="relative bg-gradient-to-r from-blue-500 to-indigo-600 text-white overflow-hidden">
      
      {/* Navbar */}
      <nav className="flex items-center justify-between px-4 sm:px-6 py-4 max-w-7xl mx-auto">
        {/* Logo + Church Name */}
        <div className="flex items-center space-x-3">
          <img
            src={Logo}
            alt="My Church Logo"
            className="h-12 w-12 sm:h-16 sm:w-16 md:h-20 md:w-20 object-contain shadow-2xl rounded-full transform hover:scale-110 transition duration-300"
          />
          <span className="text-xl sm:text-2xl md:text-4xl font-bold drop-shadow-lg">
            My Church
          </span>
        </div>

        {/* Desktop Menu */}
        <ul className="hidden md:flex space-x-6 text-lg">
          {menuItems.map((item) => (
            <li key={item}>
              <a
                href={`#${item.toLowerCase()}`}
                className="hover:text-gray-200 transition-colors duration-300"
              >
                {item}
              </a>
            </li>
          ))}
        </ul>

        {/* Mobile Menu Button */}
        <button
          className="md:hidden flex flex-col space-y-1 focus:outline-none"
          onClick={() => setIsOpen(!isOpen)}
        >
          <span className="w-6 h-0.5 bg-white"></span>
          <span className="w-6 h-0.5 bg-white"></span>
          <span className="w-6 h-0.5 bg-white"></span>
        </button>
      </nav>

      {/* Mobile Dropdown Menu */}
      {isOpen && (
        <ul className="md:hidden flex flex-col items-center space-y-4 py-4 bg-indigo-700">
          {menuItems.map((item) => (
            <li key={item}>
              <a
                href={`#${item.toLowerCase()}`}
                className="text-lg hover:text-gray-200 transition-colors duration-300"
              >
                {item}
              </a>
            </li>
          ))}
        </ul>
      )}

      {/* Hero Section */}
      <div className="relative flex flex-col items-center justify-center text-center h-[75vh] sm:h-[80vh] px-4 sm:px-6 z-10">
        {/* Decorative blurred shapes */}
        <div className="absolute top-0 left-0 w-40 sm:w-72 h-40 sm:h-72 bg-yellow-300 rounded-full mix-blend-multiply filter blur-3xl opacity-30 animate-float"></div>
        <div className="absolute bottom-0 right-0 w-56 sm:w-96 h-56 sm:h-96 bg-pink-400 rounded-full mix-blend-multiply filter blur-3xl opacity-30 animate-float" style={{ animationDelay: "3s" }}></div>

        {/* Left floating 3D image */}
        <img
          src={LeftImage}
          alt="Left 3D"
          className="absolute left-0 bottom-0 w-28 sm:w-64 md:w-80 object-contain"
        />

        {/* Right floating 3D image */}
        <img
          src={RightImage}
          alt="Right 3D"
          className="absolute right-0 bottom-0 w-28 sm:w-60 md:w-72 object-contain"
        />

        {/* Big Center Logo */}
        <img
          src={Logo}
          alt="My Church Logo"
          className="h-24 w-24 sm:h-36 sm:w-36 md:h-48 md:w-48 mb-6 object-contain shadow-2xl rounded-full transform hover:-translate-y-2 hover:scale-110 transition duration-500"
        />

        <h1 className="text-3xl sm:text-4xl md:text-6xl font-extrabold mb-4 drop-shadow-2xl">
          Welcome to My Church
        </h1>
        <p className="text-lg sm:text-xl md:text-2xl mb-8 drop-shadow-lg px-2">
          Join us in worship and community
        </p>

        {/* Buttons */}
        <div className="flex flex-col sm:flex-row gap-4 sm:gap-6">
          <a
            href="#services"
            className="bg-white text-blue-600 font-bold px-6 sm:px-8 py-3 sm:py-4 rounded-xl shadow-lg transform hover:-translate-y-1 hover:scale-105 transition duration-300"
          >
            Join Service
          </a>
          <a
            href="#donate"
            className="bg-yellow-400 text-gray-900 font-bold px-6 sm:px-8 py-3 sm:py-4 rounded-xl shadow-lg transform hover:-translate-y-1 hover:scale-105 transition duration-300"
          >
            Donate
          </a>
        </div>
      </div>
    </header>
  );
};

export default HeroWithNavbar;
