import React from "react";

const services = [
  { day: "Sunday", time: "10:00 AM", description: "Weekly Worship Service" },
  { day: "Wednesday", time: "7:00 PM", description: "Bible Study & Prayer" },
  { day: "Friday", time: "6:30 PM", description: "Youth Fellowship" },
];

const Services = () => {
  return (
    <section
      id="services"
      className="py-20 px-4 md:px-16 bg-gradient-to-b from-indigo-50 via-blue-50 to-blue-100 relative overflow-hidden"
    >
      {/* Decorative shapes for depth */}
      <div className="absolute top-0 left-0 w-72 h-72 bg-pink-300 rounded-full mix-blend-multiply filter blur-3xl opacity-30"></div>
      <div className="absolute bottom-0 right-0 w-96 h-96 bg-yellow-300 rounded-full mix-blend-multiply filter blur-3xl opacity-30"></div>

      <h2 className="text-3xl md:text-4xl font-bold mb-12 text-center text-blue-900 drop-shadow-lg">
        Weekly Services
      </h2>

      <div className="grid md:grid-cols-3 gap-10 relative z-10">
        {services.map((service) => (
          <div
            key={service.day}
            className="bg-gradient-to-r from-white to-blue-50 rounded-3xl p-8 text-center shadow-2xl hover:shadow-3xl transform hover:-translate-y-3 hover:scale-105 transition duration-500"
          >
            <h3 className="text-2xl font-bold mb-2 text-blue-800 drop-shadow-md">
              {service.day}
            </h3>
            <p className="text-gray-700 mb-4">{service.time}</p>
            <p className="text-gray-700">{service.description}</p>
          </div>
        ))}
      </div>
    </section>
  );
};

export default Services;
