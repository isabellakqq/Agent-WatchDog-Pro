import { useState, useEffect, useCallback } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../components/ui/card";
import { Badge } from "../components/ui/badge";
import { Input } from "../components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";
import { Search } from "lucide-react";
import { AlertEvent } from "../types";
import { fetchEvents } from "../api";

export function Events() {
  const [allEvents, setAllEvents] = useState<AlertEvent[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");

  const loadEvents = useCallback(async () => {
    try {
      const events = await fetchEvents();
      setAllEvents(events);
    } catch (err) {
      console.error("Failed to fetch events:", err);
    }
  }, []);

  useEffect(() => {
    loadEvents();
    const interval = setInterval(loadEvents, 5000);
    return () => clearInterval(interval);
  }, [loadEvents]);

  const filteredAlerts = allEvents.filter((alert) => {
    const matchesSearch =
      alert.processName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      alert.filePath.toLowerCase().includes(searchQuery.toLowerCase()) ||
      alert.pid.toString().includes(searchQuery);

    const matchesStatus = statusFilter === "all" || alert.status === statusFilter;
    const matchesSeverity = severityFilter === "all" || alert.severity === severityFilter;

    return matchesSearch && matchesStatus && matchesSeverity;
  });

  const getStatusBadge = (status: AlertEvent["status"]) => {
    switch (status) {
      case "active":
        return <Badge variant="destructive">活跃</Badge>;
      case "blocked":
        return <Badge className="bg-gray-900">已阻断</Badge>;
      case "ignored":
        return <Badge variant="secondary">已忽略</Badge>;
    }
  };

  const getSeverityBadge = (severity: AlertEvent["severity"]) => {
    switch (severity) {
      case "high":
        return <Badge variant="destructive">高危</Badge>;
      case "medium":
        return <Badge className="bg-orange-500">中危</Badge>;
      case "low":
        return <Badge variant="outline">低危</Badge>;
    }
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString("zh-CN", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-gray-900 mb-2">事件历史</h1>
        <p className="text-gray-500">查看和���索所有安全告警事件记录</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>筛选条件</CardTitle>
          <CardDescription>使用搜索和过滤器来查找特定事件</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col sm:flex-row gap-4">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
              <Input
                placeholder="搜索进程名、文件路径或 PID..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9"
              />
            </div>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-full sm:w-[180px]">
                <SelectValue placeholder="状态筛选" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">全部状态</SelectItem>
                <SelectItem value="active">活跃</SelectItem>
                <SelectItem value="blocked">已阻断</SelectItem>
                <SelectItem value="ignored">已忽略</SelectItem>
              </SelectContent>
            </Select>
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger className="w-full sm:w-[180px]">
                <SelectValue placeholder="危险级别" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">全部级别</SelectItem>
                <SelectItem value="high">高危</SelectItem>
                <SelectItem value="medium">中危</SelectItem>
                <SelectItem value="low">低危</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>事件列表</CardTitle>
              <CardDescription>共找到 {filteredAlerts.length} 条记录</CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="border rounded-lg">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>时间</TableHead>
                  <TableHead>进程</TableHead>
                  <TableHead>PID</TableHead>
                  <TableHead>文件路径</TableHead>
                  <TableHead>危险级别</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>处理时间</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredAlerts.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-8 text-gray-500">
                      未找到匹配的事件记录
                    </TableCell>
                  </TableRow>
                ) : (
                  filteredAlerts.map((alert) => (
                    <TableRow key={alert.id}>
                      <TableCell className="font-mono text-sm">
                        {formatTimestamp(alert.timestamp)}
                      </TableCell>
                      <TableCell>
                        <code className="px-2 py-1 bg-gray-100 rounded text-sm">
                          {alert.processName}
                        </code>
                      </TableCell>
                      <TableCell>
                        <code className="text-sm">{alert.pid}</code>
                      </TableCell>
                      <TableCell className="max-w-xs truncate font-mono text-xs">
                        {alert.filePath}
                      </TableCell>
                      <TableCell>{getSeverityBadge(alert.severity)}</TableCell>
                      <TableCell>{getStatusBadge(alert.status)}</TableCell>
                      <TableCell className="font-mono text-sm text-gray-500">
                        {alert.actionTimestamp
                          ? formatTimestamp(alert.actionTimestamp)
                          : "-"}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
