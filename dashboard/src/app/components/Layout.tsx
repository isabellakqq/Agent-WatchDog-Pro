import { Link, Outlet, useLocation } from "react-router";
import { Shield, Flame, Activity, Settings, List, Bot } from "lucide-react";
import { cn } from "./ui/utils";

export function Layout() {
  const location = useLocation();

  const navItems = [
    { path: "/", label: "监控面板", icon: Activity },
    { path: "/events", label: "事件历史", icon: List },
    { path: "/firewall", label: "防火墙", icon: Flame },
    { path: "/agent-demo", label: "Agent 对抗", icon: Bot },
    { path: "/processes", label: "进程监控", icon: Shield },
    { path: "/configuration", label: "配置管理", icon: Settings },
  ];

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white border-b border-gray-200 sticky top-0 z-50">
        <div className="px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-red-500 rounded-lg flex items-center justify-center">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="font-semibold text-gray-900">Agent-WatchDog</h1>
              <p className="text-sm text-gray-500">AI Agent 安全监控系统</p>
            </div>
          </div>
        </div>
      </header>

      <div className="flex">
        {/* Sidebar */}
        <aside className="w-64 bg-white border-r border-gray-200 min-h-[calc(100vh-73px)] sticky top-[73px]">
          <nav className="p-4">
            <ul className="space-y-1">
              {navItems.map((item) => {
                const isActive =
                  location.pathname === item.path ||
                  (item.path !== "/" && location.pathname.startsWith(item.path));
                const Icon = item.icon;
                return (
                  <li key={item.path}>
                    <Link
                      to={item.path}
                      className={cn(
                        "flex items-center gap-3 px-4 py-3 rounded-lg transition-colors",
                        isActive
                          ? "bg-red-50 text-red-600"
                          : "text-gray-700 hover:bg-gray-50"
                      )}
                    >
                      <Icon className="w-5 h-5" />
                      <span>{item.label}</span>
                    </Link>
                  </li>
                );
              })}
            </ul>
          </nav>
        </aside>

        {/* Main Content */}
        <main className="flex-1 p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
