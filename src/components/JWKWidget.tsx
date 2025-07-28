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
      width: "100%",
      height: "100%",
      margin: 0,
      padding: 0,
      background: "transparent",
      display: "flex",
      flexDirection: "column",
      boxSizing: "border-box",
      overflow: "hidden"
    }}>
      <TabNavigation activeTab={activeTab} setActiveTab={setActiveTab} />
      <div style={{ 
        marginTop: "60px", 
        flex: 1, 
        height: "calc(100% - 60px)",
        overflow: "auto",
        padding: "16px"
      }}>
        <div style={{ display: activeTab === "pem-to-jwk" ? "block" : "none", height: "100%" }}>
          <PEMToJWK />
        </div>
        <div style={{ display: activeTab === "jwk-to-pem" ? "block" : "none", height: "100%" }}>
          <JWKToPEM />
        </div>
        <div style={{ display: activeTab === "generate-new-key" ? "block" : "none", height: "100%" }}>
          <GenerateNewKey />
        </div>
      </div>
    </div>
  );
};

export default JWKWidget;
