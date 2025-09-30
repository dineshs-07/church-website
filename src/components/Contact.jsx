import React, { useState } from "react";

const Contact = () => {
  const [form, setForm] = useState({ name: "", email: "", message: "" });

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    alert(`Thank you, ${form.name}! Your message has been sent.`);
    setForm({ name: "", email: "", message: "" });
  };

  return (
    <section id="contact" className="py-20 bg-gradient-to-b from-blue-50 via-blue-100 to-blue-200 relative overflow-hidden">
      {/* Floating background shapes */}
      <div className="absolute top-0 left-0 w-72 h-72 bg-yellow-300 rounded-full mix-blend-multiply filter blur-3xl opacity-30 animate-float"></div>
      <div className="absolute bottom-0 right-0 w-96 h-96 bg-blue-400 rounded-full mix-blend-multiply filter blur-3xl opacity-30 animate-float" style={{ animationDelay: "3s" }}></div>

      <div className="container mx-auto px-6 relative z-10">
        <h2 className="text-4xl font-bold text-blue-900 mb-10 text-center drop-shadow-lg">
          Contact Us
        </h2>

        <div className="max-w-md mx-auto bg-blue-50 rounded-3xl shadow-lg p-8 transform hover:scale-105 transition duration-500">
          <form onSubmit={handleSubmit} className="space-y-4">
            <input
              type="text"
              name="name"
              value={form.name}
              onChange={handleChange}
              placeholder="Name"
              required
              className="w-full p-3 rounded-xl border border-gray-300 focus:ring-2 focus:ring-blue-500 transition"
            />
            <input
              type="email"
              name="email"
              value={form.email}
              onChange={handleChange}
              placeholder="Email"
              required
              className="w-full p-3 rounded-xl border border-gray-300 focus:ring-2 focus:ring-blue-500 transition"
            />
            <textarea
              name="message"
              value={form.message}
              onChange={handleChange}
              placeholder="Message"
              rows="4"
              required
              className="w-full p-3 rounded-xl border border-gray-300 focus:ring-2 focus:ring-blue-500 transition"
            ></textarea>
            <button
              type="submit"
              className="bg-blue-600 text-white font-semibold px-6 py-3 rounded-xl shadow-md transform hover:-translate-y-1 hover:scale-105 transition duration-300"
            >
              Send Message
            </button>
          </form>

          <p className="text-center mt-6 text-gray-700 text-sm">
            Address: 123 Church St, Your City
            <br />
            Phone: +91 1234567890
            <br />
            Email: contact@fullgospelministrieschurch.com
          </p>
        </div>
      </div>
    </section>
  );
};

export default Contact;
