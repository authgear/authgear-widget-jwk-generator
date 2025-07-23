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
      borderRadius: 8, 
      border: "1px solid #e9ecef",
      padding: 24 
    }}>
      <TabNavigation activeTab={activeTab} setActiveTab={setActiveTab} />
      <div style={{ marginTop: 24 }}>
        {activeTab === "pem-to-jwk" && <PEMToJWK />}
        {activeTab === "jwk-to-pem" && <JWKToPEM />}
        {activeTab === "generate-new-key" && <GenerateNewKey />}
      </div>
    </div>
  );
};

export default JWKWidget;
