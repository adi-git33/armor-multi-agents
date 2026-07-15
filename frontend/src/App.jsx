import { useState } from "react";
import "./App.css";
import AppNav from "./components/AppNav/AppNav";
import LiveDashboardPage from "./pages/LiveDashboard/LiveDashboardPage";
import ValidationPage from "./pages/Validation/ValidationPage";

// Nav toggle instead of react-router: this is a 2-screen internal tool, not
// a site with deep-linkable routes, and a toggle avoids adding a
// BrowserRouter/Routes layer (+ touching main.jsx) for what a few lines of
// state already solve. Both pages stay mounted (display:none on the
// inactive one) rather than conditionally rendered, so the live dashboard's
// WebSocket and the validation page's last run both survive switching tabs.
function App() {
  const [tab, setTab] = useState("live");

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100vh" }}>
      <AppNav tab={tab} setTab={setTab} />
      <div style={{ flex: 1, minHeight: 0, display: tab === "live" ? "flex" : "none", flexDirection: "column" }}>
        <LiveDashboardPage />
      </div>
      <div style={{ flex: 1, minHeight: 0, display: tab === "validation" ? "block" : "none", overflowY: "auto" }}>
        <ValidationPage />
      </div>
    </div>
  );
}

export default App;
