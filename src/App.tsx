import React from "react";
import JWKWidget from "./components/JWKWidget";

const App: React.FC = () => {
  return (
    <div style={{ 
      fontFamily: 'Inter, sans-serif', 
      minHeight: '100vh', 
      background: '#fff',
      margin: 0,
      padding: 0,
      color: '#495057'
    }}>
      <JWKWidget />
    </div>
  );
};

export default App;
