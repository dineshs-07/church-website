import React from "react";
import Hero from "./components/Hero";
import About from "./components/About";
import EmpoweringPastors from "./components/EmpoweringPastors";
import Services from "./components/Services";
import SocialWorks from "./components/SocialWorks";
import Events from "./components/Events";
import Gallery from "./components/Gallery";
import Donate from "./components/Donate";
import Contact from "./components/Contact";
import Footer from "./components/Footer";

function App() {
  return (
    <div className="App font-sans">
      <Hero />
      <About />
      <EmpoweringPastors/>
      <Services />
      <SocialWorks />
      <Events />
      <Gallery />
      <Donate />
      <Contact />
      <Footer />
    </div>
  );
}

export default App;
