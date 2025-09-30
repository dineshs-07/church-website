import React from "react";

const images = [
  "/images/event1.jpg",
  "/images/event2.jpg",
  "/images/event3.jpg",
  "/images/event4.jpg",
  "/images/event5.jpg",
  "/images/event6.jpg",
];

const Gallery = () => {
  return (
    <section id="gallery" className="py-20 bg-gradient-to-b from-pink-50 via-pink-100 to-pink-200 relative overflow-hidden">
      {/* Floating background shapes */}
      <div className="absolute top-0 left-0 w-72 h-72 bg-yellow-300 rounded-full mix-blend-multiply filter blur-3xl opacity-30 animate-float"></div>
      <div className="absolute bottom-0 right-0 w-96 h-96 bg-pink-400 rounded-full mix-blend-multiply filter blur-3xl opacity-30 animate-float" style={{ animationDelay: "3s" }}></div>

      <div className="container mx-auto px-6 relative z-10">
        <h2 className="text-4xl font-bold text-pink-800 mb-12 text-center drop-shadow-lg">
          Gallery
        </h2>
        <div className="grid sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-8">
          {images.map((img, idx) => (
            <div
              key={idx}
              className="overflow-hidden rounded-3xl shadow-2xl transform hover:-translate-y-3 hover:scale-105 transition duration-500 bg-white"
            >
              <img
                src={img}
                alt={`Church event ${idx + 1}`}
                className="w-full h-64 object-cover"
                loading="lazy"
              />
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default Gallery;
