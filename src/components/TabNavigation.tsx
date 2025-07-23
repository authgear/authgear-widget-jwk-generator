import React from "react";

type TabType = "pem-to-jwk" | "jwk-to-pem" | "generate-new-key";

interface TabNavigationProps {
  activeTab: TabType;
  setActiveTab: (tab: TabType) => void;
}

const TabNavigation: React.FC<TabNavigationProps> = ({ activeTab, setActiveTab }) => {
  return (
    <div style={{ 
      display: "flex", 
      borderBottom: "1px solid #eee",
      fontFamily: 'Inter, sans-serif',
      justifyContent: "flex-start",
      gap: 0
    }}>
      <button
        className={"tab-btn" + (activeTab === "pem-to-jwk" ? " active" : "")}
        style={{
          padding: "12px 24px",
          border: "none",
          borderBottom: activeTab === "pem-to-jwk" ? "2px solid rgb(11, 99, 233)" : "2px solid transparent",
          background: "none",
          fontWeight: 600,
          color: activeTab === "pem-to-jwk" ? "rgb(11, 99, 233)" : "#495057",
          cursor: "pointer",
          outline: "none",
          fontSize: 16,
          fontFamily: 'Inter, sans-serif',
          marginRight: 0,
          minWidth: "auto"
        }}
        onClick={() => setActiveTab("pem-to-jwk")}
      >
        PEM to JWK
      </button>
      <button
        className={"tab-btn" + (activeTab === "jwk-to-pem" ? " active" : "")}
        style={{
          padding: "12px 24px",
          border: "none",
          borderBottom: activeTab === "jwk-to-pem" ? "2px solid rgb(11, 99, 233)" : "2px solid transparent",
          background: "none",
          fontWeight: 600,
          color: activeTab === "jwk-to-pem" ? "rgb(11, 99, 233)" : "#495057",
          cursor: "pointer",
          outline: "none",
          fontSize: 16,
          fontFamily: 'Inter, sans-serif',
          marginRight: 0,
          minWidth: "auto"
        }}
        onClick={() => setActiveTab("jwk-to-pem")}
      >
        JWK to PEM
      </button>
      <button
        className={"tab-btn" + (activeTab === "generate-new-key" ? " active" : "")}
        style={{
          padding: "12px 24px",
          border: "none",
          borderBottom: activeTab === "generate-new-key" ? "2px solid rgb(11, 99, 233)" : "2px solid transparent",
          background: "none",
          fontWeight: 600,
          color: activeTab === "generate-new-key" ? "rgb(11, 99, 233)" : "#495057",
          cursor: "pointer",
          outline: "none",
          fontSize: 16,
          fontFamily: 'Inter, sans-serif',
          marginRight: 0,
          minWidth: "auto"
        }}
        onClick={() => setActiveTab("generate-new-key")}
      >
        Generate new key
      </button>
    </div>
  );
};

export default TabNavigation;
