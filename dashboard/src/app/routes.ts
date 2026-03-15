import { createBrowserRouter } from "react-router";
import { Dashboard } from "./pages/Dashboard";
import { Events } from "./pages/Events";
import { Configuration } from "./pages/Configuration";
import { Processes } from "./pages/Processes";
import { Firewall } from "./pages/Firewall";
import { AgentDemo } from "./pages/AgentDemo";
import { Layout } from "./components/Layout";

export const router = createBrowserRouter([
  {
    path: "/",
    Component: Layout,
    children: [
      { index: true, Component: Dashboard },
      { path: "events", Component: Events },
      { path: "firewall", Component: Firewall },
      { path: "agent-demo", Component: AgentDemo },
      { path: "configuration", Component: Configuration },
      { path: "processes", Component: Processes },
    ],
  },
]);
