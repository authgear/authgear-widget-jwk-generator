import React, { useState } from "react";
import TabNavigation from "./TabNavigation";
import PEMToJWK from "./PEMToJWK";
import JWKToPEM from "./JWKToPEM";
import GenerateNewKey from "./GenerateNewKey";

type TabType = "pem-to-jwk" | "jwk-to-pem" | "generate-new-key";

const JWKWidget: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabType>("pem-to-jwk");

  return (
    <div className="jwk-widget" style={{ 
      maxWidth: 1200, 
      margin: "0 auto", 
      background: "#fff", 
      padding: 0 
    }}>
      <TabNavigation activeTab={activeTab} setActiveTab={setActiveTab} />
      <div style={{ marginTop: 0 }}>
        <div style={{ display: activeTab === "pem-to-jwk" ? "block" : "none" }}>
          <PEMToJWK />
        </div>
        <div style={{ display: activeTab === "jwk-to-pem" ? "block" : "none" }}>
          <JWKToPEM />
        </div>
        <div style={{ display: activeTab === "generate-new-key" ? "block" : "none" }}>
          <GenerateNewKey />
        </div>
      </div>
    </div>
  );
};

export default JWKWidget;
