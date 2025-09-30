import React from "react";

const events = [
  {
    title: "Christmas Service",
    date: "25 Dec 2025",
    time: "10:00 AM",
    location: "Main Hall",
  },
  {
    title: "Easter Celebration",
    date: "17 Apr 2026",
    time: "9:30 AM",
    location: "Church Grounds",
  },
  {
    title: "Youth Retreat",
    date: "12 Aug 2025",
    time: "8:00 AM",
    location: "Camp Site",
  },
];

const Events = () => {
  return (
    <section id="events" className="py-20 bg-gradient-to-b from-yellow-50 via-yellow-100 to-yellow-200 relative overflow-hidden">
      {/* Floating background shapes */}
      <div className="absolute top-0 left-0 w-72 h-72 bg-pink-300 rounded-full mix-blend-multiply filter blur-3xl opacity-30 animate-float"></div>
      <div className="absolute bottom-0 right-0 w-96 h-96 bg-yellow-300 rounded-full mix-blend-multiply filter blur-3xl opacity-30 animate-float" style={{ animationDelay: "3s" }}></div>

      <div className="container mx-auto px-6 relative z-10">
        <h2 className="text-4xl font-bold text-yellow-800 mb-10 text-center drop-shadow-lg">
          Upcoming Events
        </h2>
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-8">
          {events.map((event, idx) => (
            <div
              key={idx}
              className="bg-gradient-to-r from-white to-yellow-50 p-6 rounded-3xl shadow-2xl hover:shadow-3xl transform hover:-translate-y-3 hover:scale-105 transition duration-500"
            >
              <h3 className="text-2xl font-bold text-yellow-700 mb-2 drop-shadow-md">
                {event.title}
              </h3>
              <p className="text-gray-700 font-medium">
                📅 {event.date} &nbsp; | &nbsp; ⏰ {event.time}
              </p>
              <p className="text-gray-600 mt-2">📍 {event.location}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default Events;
