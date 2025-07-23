import React from "react";
import JWKWidget from "./components/JWKWidget";

const App: React.FC = () => {
  return (
    <div style={{ 
      fontFamily: 'Inter, sans-serif', 
      minHeight: '100vh', 
      background: '#f7f7f7',
      padding: '20px',
      color: '#495057'
    }}>
      <JWKWidget />
    </div>
  );
};

export default App;
