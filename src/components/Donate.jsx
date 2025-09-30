import React from "react";

const Donate = () => {
  const handleDonate = () => {
    window.location.href = "https://www.yourchurchdonationsite.com";
  };

  return (
    <section id="donate" className="py-20 bg-gradient-to-b from-green-50 via-green-100 to-green-200 relative overflow-hidden">
      {/* Floating background shapes */}
      <div className="absolute top-0 left-0 w-72 h-72 bg-yellow-300 rounded-full mix-blend-multiply filter blur-3xl opacity-30 animate-float"></div>
      <div className="absolute bottom-0 right-0 w-96 h-96 bg-green-400 rounded-full mix-blend-multiply filter blur-3xl opacity-30 animate-float" style={{ animationDelay: "3s" }}></div>

      <div className="container mx-auto px-6 relative z-10 text-center">
        <h2 className="text-4xl font-bold text-green-800 mb-6 drop-shadow-lg">
          Support Us
        </h2>
        <p className="text-lg text-gray-700 mb-10 max-w-2xl mx-auto leading-relaxed">
          Your donations help us continue our mission and serve the community.
          Every contribution, no matter the size, makes a difference.
        </p>
        <button
          onClick={handleDonate}
          className="bg-green-500 text-white font-bold px-10 py-4 rounded-2xl shadow-2xl transform hover:-translate-y-2 hover:scale-105 transition duration-500"
        >
          Donate Now
        </button>
      </div>
    </section>
  );
};

export default Donate;
