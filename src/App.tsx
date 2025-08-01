import React from "react";
import JWKWidget from "./components/JWKWidget";

const App: React.FC = () => {
  return (
    <div style={{ 
      fontFamily: 'Inter, sans-serif', 
      margin: 0,
      padding: 0,
      color: '#495057',
      width: '100%',
      height: '100%',
      background: 'white'
    }}>
      <JWKWidget />
    </div>
  );
};

export default App;
