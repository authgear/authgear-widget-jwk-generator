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
      boxSizing: "border-box"
    }}>
      <TabNavigation activeTab={activeTab} setActiveTab={setActiveTab} />
      <div style={{ 
        marginTop: "60px", 
        flex: 1, 
        height: "calc(100% - 60px)",
        minHeight: "calc(100% - 60px)",
        overflow: "auto",
        padding: "0px 16px 16px 16px",
        boxSizing: "border-box"
      }}>
        <div style={{ 
          display: activeTab === "pem-to-jwk" ? "block" : "none", 
          height: "100%",
          minHeight: "100%",
          overflow: "visible"
        }}>
          <PEMToJWK />
        </div>
        <div style={{ 
          display: activeTab === "jwk-to-pem" ? "block" : "none", 
          height: "100%",
          minHeight: "100%",
          overflow: "visible"
        }}>
          <JWKToPEM />
        </div>
        <div style={{ 
          display: activeTab === "generate-new-key" ? "block" : "none", 
          height: "100%",
          minHeight: "100%",
          overflow: "visible"
        }}>
          <GenerateNewKey />
        </div>
      </div>
    </div>
  );
};

export default JWKWidget;
