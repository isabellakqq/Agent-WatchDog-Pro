import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../components/ui/card";
import { Badge } from "../components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";
import { Switch } from "../components/ui/switch";
import { Progress } from "../components/ui/progress";
import { mockProcesses } from "../data/mockData";
import { ProcessInfo } from "../types";
import { Activity, User, Clock } from "lucide-react";
import { toast } from "sonner";

export function Processes() {
  const [processes, setProcesses] = useState<ProcessInfo[]>(mockProcesses);

  const toggleMonitoring = (pid: number) => {
    setProcesses((prev) =>
      prev.map((p) =>
        p.pid === pid ? { ...p, isMonitored: !p.isMonitored } : p
      )
    );
    const process = processes.find((p) => p.pid === pid);
    if (process?.isMonitored) {
      toast.info(`已停止监控进程 ${process.name} (PID: ${pid})`);
    } else {
      toast.success(`已开始监控进程 ${process?.name} (PID: ${pid})`);
    }
  };

  const getRiskColor = (score: number) => {
    if (score >= 70) return "text-red-600";
    if (score >= 40) return "text-orange-500";
    return "text-green-600";
  };

  const getRiskLevel = (score: number) => {
    if (score >= 70) return "高风险";
    if (score >= 40) return "中风险";
    return "低风险";
  };

  const formatUptime = (startTime: string) => {
    const start = new Date(startTime);
    const now = new Date();
    const diffMs = now.getTime() - start.getTime();
    const diffHours = Math.floor(diffMs / 3600000);
    const diffMins = Math.floor((diffMs % 3600000) / 60000);

    if (diffHours > 0) {
      return `${diffHours} 小时 ${diffMins} 分钟`;
    }
    return `${diffMins} 分钟`;
  };

  const monitoredCount = processes.filter((p) => p.isMonitored).length;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-gray-900 mb-2">进程监控</h1>
        <p className="text-gray-500">实时监控系统中的进程及其风险评分</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardHeader className="pb-3">
            <CardDescription>总进程数</CardDescription>
            <CardTitle className="text-3xl">{processes.length}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2 text-sm text-gray-500">
              <Activity className="w-4 h-4" />
              <span>当前运行</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardDescription>已监控进程</CardDescription>
            <CardTitle className="text-3xl text-green-600">{monitoredCount}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2 text-sm text-gray-500">
              <Activity className="w-4 h-4" />
              <span>实时保护中</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardDescription>高风险进程</CardDescription>
            <CardTitle className="text-3xl text-red-600">
              {processes.filter((p) => p.riskScore >= 70).length}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2 text-sm text-gray-500">
              <Activity className="w-4 h-4" />
              <span>需要关注</span>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Process List */}
      <Card>
        <CardHeader>
          <CardTitle>进程列表</CardTitle>
          <CardDescription>管理和监控系统进程的风险等级</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="border rounded-lg">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>PID</TableHead>
                  <TableHead>进程名</TableHead>
                  <TableHead>用户</TableHead>
                  <TableHead>运行时长</TableHead>
                  <TableHead>风险评分</TableHead>
                  <TableHead>风险等级</TableHead>
                  <TableHead>监控状态</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {processes.map((process) => (
                  <TableRow key={process.pid}>
                    <TableCell>
                      <code className="text-sm font-mono">{process.pid}</code>
                    </TableCell>
                    <TableCell>
                      <code className="px-2 py-1 bg-gray-100 rounded text-sm">
                        {process.name}
                      </code>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <User className="w-4 h-4 text-gray-400" />
                        <span className="text-sm">{process.user}</span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2 text-sm text-gray-600">
                        <Clock className="w-4 h-4" />
                        {formatUptime(process.startTime)}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="space-y-2 min-w-[120px]">
                        <div className="flex items-center justify-between">
                          <span className={`text-sm font-medium ${getRiskColor(process.riskScore)}`}>
                            {process.riskScore}
                          </span>
                          <span className="text-xs text-gray-500">/ 100</span>
                        </div>
                        <Progress value={process.riskScore} className="h-2" />
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={
                          process.riskScore >= 70
                            ? "destructive"
                            : process.riskScore >= 40
                            ? "default"
                            : "secondary"
                        }
                      >
                        {getRiskLevel(process.riskScore)}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <Switch
                          checked={process.isMonitored}
                          onCheckedChange={() => toggleMonitoring(process.pid)}
                        />
                        <span className="text-sm text-gray-600">
                          {process.isMonitored ? "已启用" : "已禁用"}
                        </span>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
