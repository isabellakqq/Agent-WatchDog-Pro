import { useState, useEffect, useCallback } from "react";
import { AlertTriangle, Ban, Eye, Activity, Clock, Shield } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../components/ui/card";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { AlertEvent, SystemStats } from "../types";
import { toast } from "sonner";
import {
  fetchStats,
  fetchAlerts,
  blockEvent,
  ignoreEvent,
  connectWebSocket,
} from "../api";

export function Dashboard() {
  const [alerts, setAlerts] = useState<AlertEvent[]>([]);
  const [stats, setStats] = useState<SystemStats>({
    todayAlerts: 0,
    activeAlerts: 0,
    blockedProcesses: 0,
    ignoredAlerts: 0,
    totalAlerts: 0,
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // ── Fetch data from backend ────────────────────────────────
  const refreshData = useCallback(async () => {
    try {
      const [s, a] = await Promise.all([fetchStats(), fetchAlerts()]);
      setStats(s);
      setAlerts(a);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to connect to backend");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshData();
    const interval = setInterval(refreshData, 5000);
    return () => clearInterval(interval);
  }, [refreshData]);

  // ── WebSocket for real-time events ─────────────────────────
  useEffect(() => {
    const cleanup = connectWebSocket((newEvent) => {
      setAlerts((prev) => [newEvent, ...prev.filter((e) => e.id !== newEvent.id)]);
      fetchStats().then(setStats).catch(console.error);
      toast.warning("New alert detected!", {
        description: `${newEvent.processName} (PID: ${newEvent.pid}) → ${newEvent.filePath}`,
      });
    });
    return cleanup;
  }, []);

  // ── Actions ────────────────────────────────────────────────
  const handleAction = async (id: string, action: "block" | "ignore") => {
    try {
      const res = action === "block" ? await blockEvent(id) : await ignoreEvent(id);
      if (res.success) {
        setAlerts((prev) =>
          prev.map((alert) =>
            alert.id === id
              ? {
                ...alert,
                status: action === "block" ? ("blocked" as const) : ("ignored" as const),
                actionTimestamp: new Date().toISOString(),
              }
              : alert
          )
        );
        fetchStats().then(setStats).catch(console.error);

        if (action === "block") {
          toast.success("进程已成功阻断", {
            description: `PID ${alerts.find((a) => a.id === id)?.pid} 已被终止`,
          });
        } else {
          toast.info("告警已标记为误报");
        }
      }
    } catch (err) {
      toast.error("操作失败", {
        description: err instanceof Error ? err.message : "Unknown error",
      });
    }
  };

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);

    if (diffMins < 1) return "刚刚";
    if (diffMins < 60) return `${diffMins} 分钟前`;
    if (diffMins < 1440) return `${Math.floor(diffMins / 60)} 小时前`;
    return date.toLocaleString("zh-CN");
  };

  return (
    <div className="space-y-6">
      {/* Connection error banner */}
      {error && (
        <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm">
          ⚠️ {error} — 请确认后端 Agent-WatchDog 正在运行
        </div>
      )}

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="pb-3">
            <CardDescription>今日告警</CardDescription>
            <CardTitle className="text-3xl">{stats.todayAlerts}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2 text-sm text-gray-500">
              <Clock className="w-4 h-4" />
              <span>过去 24 小时</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardDescription>活跃告警</CardDescription>
            <CardTitle className="text-3xl text-red-600">{stats.activeAlerts}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2 text-sm text-gray-500">
              <Activity className="w-4 h-4" />
              <span>需要处理</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardDescription>已阻断进程</CardDescription>
            <CardTitle className="text-3xl">{stats.blockedProcesses}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2 text-sm text-gray-500">
              <Ban className="w-4 h-4" />
              <span>历史累计</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardDescription>误报告警</CardDescription>
            <CardTitle className="text-3xl">{stats.ignoredAlerts}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2 text-sm text-gray-500">
              <Eye className="w-4 h-4" />
              <span>已忽略</span>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Active Alerts */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>实时告警</CardTitle>
              <CardDescription>需要立即处理的高危文件访问行为</CardDescription>
            </div>
            <Badge variant="destructive" className="h-6">
              {alerts.length} 个活跃告警
            </Badge>
          </div>
        </CardHeader>
        <CardContent>
          {alerts.length === 0 ? (
            <div className="text-center py-12 text-gray-500">
              <Shield className="w-12 h-12 mx-auto mb-3 opacity-50" />
              <p>暂无活跃告警</p>
              <p className="text-sm mt-1">系统运行正常，所有进程处于监控中</p>
            </div>
          ) : (
            <div className="space-y-4">
              {alerts.map((alert) => (
                <div
                  key={alert.id}
                  className="border border-red-200 bg-red-50 rounded-lg p-4"
                >
                  <div className="flex items-start gap-4">
                    <div className="w-10 h-10 bg-red-100 rounded-lg flex items-center justify-center flex-shrink-0">
                      <AlertTriangle className="w-5 h-5 text-red-600" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-2">
                        <h3 className="font-semibold text-gray-900">
                          高危文件访问行为
                        </h3>
                        <Badge variant="destructive">{alert.severity}</Badge>
                        <span className="text-sm text-gray-500 ml-auto">
                          {formatTimestamp(alert.timestamp)}
                        </span>
                      </div>
                      <div className="space-y-1 text-sm">
                        <p className="text-gray-700">
                          进程 <code className="px-2 py-0.5 bg-white rounded">{alert.processName}</code>{" "}
                          (PID: <code className="px-2 py-0.5 bg-white rounded">{alert.pid}</code>)
                          正在尝试读取敏感文件
                        </p>
                        <p className="text-gray-600">
                          文件路径: <code className="px-2 py-0.5 bg-white rounded font-mono text-xs">{alert.filePath}</code>
                        </p>
                      </div>
                      <div className="flex gap-2 mt-4">
                        <Button
                          size="sm"
                          variant="destructive"
                          onClick={() => handleAction(alert.id, "block")}
                        >
                          <Ban className="w-4 h-4 mr-2" />
                          阻断进程
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => handleAction(alert.id, "ignore")}
                        >
                          <Eye className="w-4 h-4 mr-2" />
                          标记误报
                        </Button>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
