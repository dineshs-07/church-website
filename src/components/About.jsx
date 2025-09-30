import React from "react";

const About = () => {
  return (
    <section
      id="about"
      className="py-20 bg-gradient-to-b from-blue-50 via-blue-100 to-indigo-50 relative overflow-hidden"
    >
      {/* Decorative background shapes */}
      <div className="absolute top-0 left-0 w-72 h-72 bg-blue-400 rounded-full mix-blend-multiply filter blur-3xl opacity-30"></div>
      <div className="absolute bottom-0 right-0 w-96 h-96 bg-pink-400 rounded-full mix-blend-multiply filter blur-3xl opacity-30"></div>

      <div className="container mx-auto px-6 relative z-10">
        <div className="max-w-4xl mx-auto bg-gradient-to-r from-white to-blue-50 rounded-3xl shadow-2xl p-10 transform hover:scale-105 transition duration-500">
          <h2 className="text-4xl md:text-5xl font-bold text-blue-800 mb-6 drop-shadow-lg text-center">
            About Us
          </h2>
          <p className="text-lg text-gray-800 mb-6 leading-relaxed">
            Welcome to our church! We are a community of believers dedicated to faith, service, and love. Join us to experience worship, fellowship, and spiritual growth.
          </p>
          <p className="text-lg text-gray-800 leading-relaxed">
            Our vision is to create a welcoming space for everyone, with weekly
            services, outreach programs, and spiritual growth opportunities.
          </p>
        </div>
      </div>
    </section>
  );
};

export default About;
