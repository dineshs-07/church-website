import React from "react";

const socialWorks = [
  {
    title: "Food Distribution",
    description: "Providing meals to underprivileged families every weekend.",
    image: "/images/social1.jpg",
  },
  {
    title: "Community Health Camp",
    description: "Free health checkup and medicines for the local community.",
    image: "/images/social2.jpg",
  },
  {
    title: "Tree Plantation",
    description: "Planting trees in urban areas to improve environment.",
    image: "/images/social3.jpg",
  },
  {
    title: "School Supplies Drive",
    description: "Distributing books and stationery to students in need.",
    image: "/images/social4.jpg",
  },
];

const SocialWorks = () => {
  return (
    <section
      id="social-works"
      className="py-20 bg-gradient-to-b from-green-50 via-green-100 to-green-200 relative overflow-hidden"
    >
      {/* Floating background shapes */}
      <div className="absolute top-0 left-0 w-72 h-72 bg-yellow-300 rounded-full mix-blend-multiply filter blur-3xl opacity-30 animate-float"></div>
      <div className="absolute bottom-0 right-0 w-96 h-96 bg-green-400 rounded-full mix-blend-multiply filter blur-3xl opacity-30 animate-float" style={{ animationDelay: "3s" }}></div>

      <div className="container mx-auto px-6 relative z-10">
        <h2 className="text-4xl font-bold text-green-800 mb-12 text-center drop-shadow-lg">
          Social Works
        </h2>

        <div className="grid sm:grid-cols-2 md:grid-cols-2 lg:grid-cols-4 gap-8">
          {socialWorks.map((work, idx) => (
            <div
              key={idx}
              className="overflow-hidden rounded-3xl shadow-2xl transform hover:-translate-y-3 hover:scale-105 transition duration-500 bg-white"
            >
              <img
                src={work.image}
                alt={work.title}
                className="w-full h-64 object-cover"
                loading="lazy"
              />
              <div className="p-6 text-center">
                <h3 className="text-2xl font-bold text-green-700 mb-2">{work.title}</h3>
                <p className="text-gray-700">{work.description}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default SocialWorks;
