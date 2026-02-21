import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../components/ui/card";
import { Input } from "../components/ui/input";
import { Label } from "../components/ui/label";
import { Button } from "../components/ui/button";
import { Badge } from "../components/ui/badge";
import { Switch } from "../components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../components/ui/table";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "../components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../components/ui/select";
import { mockPatterns } from "../data/mockData";
import { SensitivePattern } from "../types";
import { Save, Plus, Trash2, Eye, EyeOff } from "lucide-react";
import { toast } from "sonner";

export function Configuration() {
  const [slackWebhook, setSlackWebhook] = useState("https://hooks.slack.com/services/YOUR/WEBHOOK/URL");
  const [showWebhook, setShowWebhook] = useState(false);
  const [patterns, setPatterns] = useState<SensitivePattern[]>(mockPatterns);
  const [newPattern, setNewPattern] = useState({
    pattern: "",
    description: "",
    severity: "high" as "high" | "medium" | "low",
  });
  const [isDialogOpen, setIsDialogOpen] = useState(false);

  const handleSaveWebhook = () => {
    toast.success("Slack Webhook 配置已保存");
  };

  const togglePattern = (id: string) => {
    setPatterns((prev) =>
      prev.map((p) => (p.id === id ? { ...p, enabled: !p.enabled } : p))
    );
  };

  const deletePattern = (id: string) => {
    setPatterns((prev) => prev.filter((p) => p.id !== id));
    toast.success("规则已删除");
  };

  const addPattern = () => {
    if (!newPattern.pattern || !newPattern.description) {
      toast.error("请填写完整信息");
      return;
    }

    const pattern: SensitivePattern = {
      id: Date.now().toString(),
      pattern: newPattern.pattern,
      description: newPattern.description,
      severity: newPattern.severity,
      enabled: true,
    };

    setPatterns((prev) => [...prev, pattern]);
    setNewPattern({ pattern: "", description: "", severity: "high" });
    setIsDialogOpen(false);
    toast.success("监控规则已添加");
  };

  const getSeverityBadge = (severity: SensitivePattern["severity"]) => {
    switch (severity) {
      case "high":
        return <Badge variant="destructive">高危</Badge>;
      case "medium":
        return <Badge className="bg-orange-500">中危</Badge>;
      case "low":
        return <Badge variant="outline">低危</Badge>;
    }
  };

  const enabledCount = patterns.filter((p) => p.enabled).length;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-gray-900 mb-2">配置管理</h1>
        <p className="text-gray-500">配置 Slack 告警和敏感文件监控规则</p>
      </div>

      {/* Slack Configuration */}
      <Card>
        <CardHeader>
          <CardTitle>Slack 告警配置</CardTitle>
          <CardDescription>
            配置 Slack Webhook URL 以接收实时告警通知
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="webhook">Webhook URL</Label>
            <div className="flex gap-2">
              <div className="flex-1 relative">
                <Input
                  id="webhook"
                  type={showWebhook ? "text" : "password"}
                  value={slackWebhook}
                  onChange={(e) => setSlackWebhook(e.target.value)}
                  placeholder="https://hooks.slack.com/services/..."
                />
                <button
                  type="button"
                  onClick={() => setShowWebhook(!showWebhook)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                >
                  {showWebhook ? (
                    <EyeOff className="w-4 h-4" />
                  ) : (
                    <Eye className="w-4 h-4" />
                  )}
                </button>
              </div>
              <Button onClick={handleSaveWebhook}>
                <Save className="w-4 h-4 mr-2" />
                保存配置
              </Button>
            </div>
            <p className="text-sm text-gray-500">
              需要创建 Slack Incoming Webhook？
              <a
                href="https://api.slack.com/messaging/webhooks"
                target="_blank"
                rel="noopener noreferrer"
                className="text-blue-600 hover:underline ml-1"
              >
                查看文档
              </a>
            </p>
          </div>

          <div className="border-t pt-4">
            <h3 className="font-medium mb-2">告警消息格式</h3>
            <div className="bg-gray-50 border rounded-lg p-4 text-sm font-mono space-y-2">
              <div className="text-red-600">🚨 安全告警：高危文件访问行为</div>
              <div className="text-gray-700">进程: cat (PID: 5543)</div>
              <div className="text-gray-700">文件: /home/user/.env</div>
              <div className="text-gray-700">时间: 2026-02-20 10:30:25</div>
              <div className="flex gap-2 mt-3">
                <span className="px-3 py-1 bg-red-600 text-white rounded">阻断进程</span>
                <span className="px-3 py-1 bg-gray-300 text-gray-700 rounded">标记误报</span>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Sensitive Patterns */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>敏感文件监控规则</CardTitle>
              <CardDescription>
                定义需要监控的文件路径关键字和匹配规则 ({enabledCount}/{patterns.length} 已启用)
              </CardDescription>
            </div>
            <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
              <DialogTrigger asChild>
                <Button>
                  <Plus className="w-4 h-4 mr-2" />
                  添加规则
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>添加监控规则</DialogTitle>
                  <DialogDescription>
                    定义新的敏感文件匹配规则
                  </DialogDescription>
                </DialogHeader>
                <div className="space-y-4 pt-4">
                  <div className="space-y-2">
                    <Label htmlFor="pattern">匹配关键字</Label>
                    <Input
                      id="pattern"
                      placeholder="例如: .env, id_rsa, secret"
                      value={newPattern.pattern}
                      onChange={(e) =>
                        setNewPattern({ ...newPattern, pattern: e.target.value })
                      }
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="description">规则描述</Label>
                    <Input
                      id="description"
                      placeholder="例如: 环境变量配置文件"
                      value={newPattern.description}
                      onChange={(e) =>
                        setNewPattern({ ...newPattern, description: e.target.value })
                      }
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="severity">危险级别</Label>
                    <Select
                      value={newPattern.severity}
                      onValueChange={(value: "high" | "medium" | "low") =>
                        setNewPattern({ ...newPattern, severity: value })
                      }
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="high">高危</SelectItem>
                        <SelectItem value="medium">中危</SelectItem>
                        <SelectItem value="low">低危</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <Button onClick={addPattern} className="w-full">
                    添加规则
                  </Button>
                </div>
              </DialogContent>
            </Dialog>
          </div>
        </CardHeader>
        <CardContent>
          <div className="border rounded-lg">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>匹配关键字</TableHead>
                  <TableHead>描述</TableHead>
                  <TableHead>危险级别</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead className="text-right">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {patterns.map((pattern) => (
                  <TableRow key={pattern.id}>
                    <TableCell>
                      <code className="px-2 py-1 bg-gray-100 rounded text-sm font-mono">
                        {pattern.pattern}
                      </code>
                    </TableCell>
                    <TableCell className="text-gray-600">
                      {pattern.description}
                    </TableCell>
                    <TableCell>{getSeverityBadge(pattern.severity)}</TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <Switch
                          checked={pattern.enabled}
                          onCheckedChange={() => togglePattern(pattern.id)}
                        />
                        <span className="text-sm text-gray-600">
                          {pattern.enabled ? "已启用" : "已禁用"}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => deletePattern(pattern.id)}
                      >
                        <Trash2 className="w-4 h-4 text-red-600" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Additional Settings */}
      <Card>
        <CardHeader>
          <CardTitle>高级设置</CardTitle>
          <CardDescription>配置系统行为和监控策略</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between p-4 border rounded-lg">
            <div>
              <h3 className="font-medium">自动阻断模式</h3>
              <p className="text-sm text-gray-500">
                检测到高危行为时自动阻断进程，无需人工确认
              </p>
            </div>
            <Switch />
          </div>
          <div className="flex items-center justify-between p-4 border rounded-lg">
            <div>
              <h3 className="font-medium">详细日志记录</h3>
              <p className="text-sm text-gray-500">
                记录所有文件访问操作，包括非敏感文件
              </p>
            </div>
            <Switch />
          </div>
          <div className="flex items-center justify-between p-4 border rounded-lg">
            <div>
              <h3 className="font-medium">Slack 通知</h3>
              <p className="text-sm text-gray-500">
                检测到告警时发送 Slack 消息通知
              </p>
            </div>
            <Switch defaultChecked />
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
