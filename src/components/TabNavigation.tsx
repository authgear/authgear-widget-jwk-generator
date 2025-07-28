import React from "react";

type TabType = "pem-to-jwk" | "jwk-to-pem" | "generate-new-key";

interface TabNavigationProps {
  activeTab: TabType;
  setActiveTab: (tab: TabType) => void;
}

const TabNavigation: React.FC<TabNavigationProps> = ({ activeTab, setActiveTab }) => {
  return (
    <>
      <style>
        {`
          * {
            box-sizing: border-box;
          }
          
          @media (max-width: 768px) {
            .authgear-branding {
              display: none !important;
            }
          }
          
          @media (max-width: 768px) {
            .responsive-grid {
              grid-template-columns: 1fr !important;
              gap: 12px !important;
            }
          }
          
          @media (min-width: 769px) and (max-width: 1024px) {
            .responsive-grid {
              grid-template-columns: 1fr 1fr !important;
              gap: 12px !important;
            }
          }
        `}
      </style>
      <div style={{ 
        position: "fixed",
        top: 0,
        left: 0,
        right: 0,
        zIndex: 1000,
        display: "flex", 
        borderBottom: "1px solid #eee",
        fontFamily: 'Inter, sans-serif',
        justifyContent: "space-between",
        alignItems: "center",
        gap: 0,
        padding: "0 16px",
        width: "100%",
        background: "white",
        height: "60px"
      }}>
      <div style={{ display: "flex", gap: 0 }}>
      <button
        className={"tab-btn" + (activeTab === "pem-to-jwk" ? " active" : "")}
        style={{
          padding: "12px 24px",
          border: "none",
          borderBottom: activeTab === "pem-to-jwk" ? "2px solid rgb(11, 99, 233)" : "2px solid transparent",
          background: "none",
          fontWeight: 400,
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
          fontWeight: 400,
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
          fontWeight: 400,
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
      
                 {/* Authgear branding */}
           <div 
             className="authgear-branding"
             style={{
               display: "flex",
               alignItems: "center",
               gap: "8px",
               padding: "0 16px",
               fontSize: "12px",
               color: "#6c757d",
               fontWeight: 500
             }}
           >
        <span>Presented by</span>
        <img 
          src="./authgear-logo.svg" 
          alt="Authgear" 
          style={{
            height: "20px",
            width: "auto"
          }}
        />
      </div>
    </div>
    </>
  );
};

export default TabNavigation;
