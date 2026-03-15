import { useState, useEffect, useRef, useCallback } from "react";
import {
    Bot,
    Shield,
    ShieldCheck,
    Play,
    RotateCcw,
    ChevronRight,
    Brain,
    Wrench,
    CheckCircle,
    XCircle,
    Loader2,
    Zap,
    MessageSquare,
    ShieldAlert,
} from "lucide-react";
import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
} from "../components/ui/card";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Progress } from "../components/ui/progress";
import { toast } from "sonner";
import {
    fetchScenarios,
    runScenarioStream,
    checkFirewallHealth,
    type ScenarioInfo,
    type SSEEvent,
} from "../agentApi";

// ── Types for the timeline entries ───────────────────────────

interface TimelineEntry {
    id: string;
    type: "thinking" | "tool_call" | "firewall_result" | "agent_reaction" | "scenario_start" | "scenario_end";
    step: number;
    data: Record<string, unknown>;
    timestamp: number;
}

// ── Color helpers ────────────────────────────────────────────

const scenarioColors: Record<string, string> = {
    red: "border-red-300 bg-red-50",
    orange: "border-orange-300 bg-orange-50",
    purple: "border-purple-300 bg-purple-50",
    green: "border-green-300 bg-green-50",
    blue: "border-blue-300 bg-blue-50",
};

const scenarioAccent: Record<string, string> = {
    red: "bg-red-600",
    orange: "bg-orange-600",
    purple: "bg-purple-600",
    green: "bg-green-600",
    blue: "bg-blue-600",
};

function riskColor(score: number): string {
    if (score >= 80) return "text-red-600";
    if (score >= 50) return "text-orange-600";
    if (score >= 30) return "text-yellow-600";
    return "text-green-600";
}

// ═════════════════════════════════════════════════════════════

export function AgentDemo() {
    const [healthy, setHealthy] = useState(false);
    const [scenarios, setScenarios] = useState<ScenarioInfo[]>([]);
    const [selectedId, setSelectedId] = useState<string | null>(null);
    const [running, setRunning] = useState(false);
    const [timeline, setTimeline] = useState<TimelineEntry[]>([]);
    const [currentStep, setCurrentStep] = useState(0);
    const [totalSteps, setTotalSteps] = useState(0);
    const [scenarioResult, setScenarioResult] = useState<{
        blocked: number;
        allowed: number;
        conclusion: string;
    } | null>(null);
    const timelineEndRef = useRef<HTMLDivElement>(null);

    // ── Load scenarios ──────────────────────────────────────
    useEffect(() => {
        const load = async () => {
            try {
                const [s, h] = await Promise.all([
                    fetchScenarios(),
                    checkFirewallHealth(),
                ]);
                setScenarios(s);
                setHealthy(h);
                if (s.length > 0 && !selectedId) setSelectedId(s[0].id);
            } catch {
                setHealthy(false);
            }
        };
        load();
    }, []);

    // ── Auto-scroll timeline ────────────────────────────────
    useEffect(() => {
        timelineEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }, [timeline]);

    // ── Run scenario ────────────────────────────────────────
    const handleRun = useCallback(async () => {
        if (!selectedId || running) return;

        setTimeline([]);
        setScenarioResult(null);
        setCurrentStep(0);
        setTotalSteps(0);
        setRunning(true);

        let entryCount = 0;

        try {
            for await (const event of runScenarioStream(selectedId)) {
                entryCount++;
                const entry: TimelineEntry = {
                    id: `${entryCount}`,
                    type: event.type as TimelineEntry["type"],
                    step: (event.data as { step?: number }).step ?? 0,
                    data: event.data as unknown as Record<string, unknown>,
                    timestamp: Date.now(),
                };

                switch (event.type) {
                    case "scenario_start":
                        setTotalSteps(event.data.total_steps);
                        setTimeline((prev) => [...prev, entry]);
                        break;
                    case "thinking":
                        setCurrentStep(event.data.step);
                        setTimeline((prev) => [...prev, entry]);
                        break;
                    case "tool_call":
                    case "firewall_result":
                    case "agent_reaction":
                        setTimeline((prev) => [...prev, entry]);
                        break;
                    case "scenario_end":
                        setScenarioResult({
                            blocked: event.data.blocked,
                            allowed: event.data.allowed,
                            conclusion: event.data.conclusion,
                        });
                        setTimeline((prev) => [...prev, entry]);
                        break;
                }
            }
        } catch (err) {
            toast.error("场景执行失败", {
                description: err instanceof Error ? err.message : "连接中断",
            });
        } finally {
            setRunning(false);
        }
    }, [selectedId, running]);

    const handleReset = () => {
        setTimeline([]);
        setScenarioResult(null);
        setCurrentStep(0);
        setTotalSteps(0);
    };

    const selected = scenarios.find((s) => s.id === selectedId);
    const progress = totalSteps > 0 ? (currentStep / totalSteps) * 100 : 0;

    // ── Render ──────────────────────────────────────────────
    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-semibold text-gray-900 mb-1">
                        🤖 Agent 端到端对抗演示
                    </h1>
                    <p className="text-gray-500">
                        真实闭环：Agent 产生恶意意图 → 调用工具 → 防火墙实时拦截
                    </p>
                </div>
                <Badge
                    variant={healthy ? "default" : "destructive"}
                    className={`h-8 px-3 text-sm ${healthy ? "bg-green-600" : ""}`}
                >
                    {healthy ? (
                        <>
                            <CheckCircle className="w-4 h-4 mr-1" /> 防火墙在线
                        </>
                    ) : (
                        <>
                            <XCircle className="w-4 h-4 mr-1" /> 防火墙离线
                        </>
                    )}
                </Badge>
            </div>

            {/* Architecture Diagram */}
            <Card className="bg-gradient-to-r from-slate-50 to-blue-50 border-blue-200">
                <CardContent className="py-4">
                    <div className="flex items-center justify-center gap-3 text-sm">
                        <div className="flex items-center gap-2 bg-white px-4 py-2 rounded-lg border shadow-sm">
                            <Bot className="w-5 h-5 text-blue-600" />
                            <span className="font-semibold">AI Agent</span>
                        </div>
                        <ChevronRight className="w-5 h-5 text-gray-400" />
                        <div className="flex items-center gap-2 bg-white px-4 py-2 rounded-lg border shadow-sm">
                            <Wrench className="w-5 h-5 text-gray-600" />
                            <span>Tool Call</span>
                        </div>
                        <ChevronRight className="w-5 h-5 text-gray-400" />
                        <div className="flex items-center gap-2 bg-red-50 px-4 py-2 rounded-lg border-2 border-red-300 shadow-sm">
                            <Shield className="w-5 h-5 text-red-600" />
                            <span className="font-bold text-red-700">WatchDog 防火墙</span>
                        </div>
                        <ChevronRight className="w-5 h-5 text-gray-400" />
                        <div className="flex items-center gap-2 bg-white px-4 py-2 rounded-lg border shadow-sm">
                            <Zap className="w-5 h-5 text-green-600" />
                            <span>执行 / 拦截</span>
                        </div>
                    </div>
                </CardContent>
            </Card>

            {/* Scenario Selector */}
            <div className="grid grid-cols-1 lg:grid-cols-5 gap-3">
                {scenarios.map((s) => (
                    <Card
                        key={s.id}
                        className={`cursor-pointer transition-all ${
                            selectedId === s.id
                                ? `${scenarioColors[s.color]} ring-2 ring-offset-1 ring-${s.color}-400 shadow-md`
                                : "hover:shadow-md hover:border-gray-300"
                        }`}
                        onClick={() => {
                            if (!running) {
                                setSelectedId(s.id);
                                handleReset();
                            }
                        }}
                    >
                        <CardHeader className="pb-2 pt-4 px-4">
                            <CardTitle className="text-base">{s.title}</CardTitle>
                        </CardHeader>
                        <CardContent className="pb-3 px-4">
                            <p className="text-xs text-gray-500 line-clamp-2">
                                {s.description}
                            </p>
                            <div className="flex items-center gap-1 mt-2 text-xs text-gray-400">
                                <Wrench className="w-3 h-3" />
                                {s.step_count} 步
                            </div>
                        </CardContent>
                    </Card>
                ))}
            </div>

            {/* Task & Controls */}
            {selected && (
                <Card className={`${scenarioColors[selected.color]} border-2`}>
                    <CardHeader className="pb-3">
                        <div className="flex items-center justify-between">
                            <div>
                                <CardTitle className="flex items-center gap-2 text-lg">
                                    {selected.title}
                                </CardTitle>
                                <CardDescription className="mt-1 text-gray-600">
                                    {selected.description}
                                </CardDescription>
                            </div>
                            <div className="flex gap-2">
                                <Button
                                    onClick={handleRun}
                                    disabled={running || !healthy}
                                    className={`gap-2 ${scenarioAccent[selected.color]} hover:opacity-90`}
                                >
                                    {running ? (
                                        <>
                                            <Loader2 className="w-4 h-4 animate-spin" />
                                            执行中...
                                        </>
                                    ) : (
                                        <>
                                            <Play className="w-4 h-4" />
                                            开始演示
                                        </>
                                    )}
                                </Button>
                                <Button
                                    variant="outline"
                                    onClick={handleReset}
                                    disabled={running}
                                    className="gap-2"
                                >
                                    <RotateCcw className="w-4 h-4" />
                                    重置
                                </Button>
                            </div>
                        </div>
                    </CardHeader>
                    <CardContent>
                        <div className="bg-white/80 rounded-lg border p-4">
                            <div className="text-xs text-gray-400 mb-1 flex items-center gap-1">
                                <MessageSquare className="w-3 h-3" />
                                Agent 收到的任务指令
                            </div>
                            <p className="text-sm text-gray-800 font-mono whitespace-pre-wrap">
                                {selected.task}
                            </p>
                        </div>
                        {running && (
                            <div className="mt-3">
                                <div className="flex justify-between text-xs text-gray-500 mb-1">
                                    <span>
                                        步骤 {currentStep} / {totalSteps}
                                    </span>
                                    <span>{Math.round(progress)}%</span>
                                </div>
                                <Progress value={progress} className="h-2" />
                            </div>
                        )}
                    </CardContent>
                </Card>
            )}

            {/* Timeline */}
            {timeline.length > 0 && (
                <Card>
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2">
                            <Brain className="w-5 h-5 text-purple-600" />
                            实时对抗过程
                        </CardTitle>
                        <CardDescription>
                            左侧：Agent 推理过程 — 右侧：防火墙决策
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        <div className="space-y-3">
                            {timeline.map((entry) => (
                                <TimelineRow key={entry.id} entry={entry} />
                            ))}
                            {running && (
                                <div className="flex items-center gap-2 text-gray-400 text-sm py-2">
                                    <Loader2 className="w-4 h-4 animate-spin" />
                                    Agent 正在思考...
                                </div>
                            )}
                            <div ref={timelineEndRef} />
                        </div>
                    </CardContent>
                </Card>
            )}

            {/* Result Summary */}
            {scenarioResult && (
                <Card className="border-2 border-green-300 bg-gradient-to-r from-green-50 to-emerald-50">
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2 text-green-800">
                            <ShieldCheck className="w-6 h-6" />
                            演示结果
                        </CardTitle>
                    </CardHeader>
                    <CardContent>
                        <div className="grid grid-cols-3 gap-6 mb-4">
                            <div className="text-center">
                                <div className="text-4xl font-bold text-red-600">
                                    {scenarioResult.blocked}
                                </div>
                                <div className="text-sm text-gray-500 mt-1">
                                    恶意操作被拦截
                                </div>
                            </div>
                            <div className="text-center">
                                <div className="text-4xl font-bold text-green-600">
                                    {scenarioResult.allowed}
                                </div>
                                <div className="text-sm text-gray-500 mt-1">
                                    安全操作已放行
                                </div>
                            </div>
                            <div className="text-center">
                                <div className="text-4xl font-bold text-blue-600">
                                    {totalSteps > 0
                                        ? (
                                              (scenarioResult.blocked / totalSteps) *
                                              100
                                          ).toFixed(0)
                                        : 0}
                                    %
                                </div>
                                <div className="text-sm text-gray-500 mt-1">
                                    威胁拦截率
                                </div>
                            </div>
                        </div>
                        <div className="bg-white/80 rounded-lg border border-green-200 p-4 text-sm text-green-800">
                            {scenarioResult.conclusion}
                        </div>
                    </CardContent>
                </Card>
            )}
        </div>
    );
}

// ═════════════════════════════════════════════════════════════
//  TIMELINE ROW COMPONENT
// ═════════════════════════════════════════════════════════════

function TimelineRow({ entry }: { entry: TimelineEntry }) {
    const data = entry.data;

    switch (entry.type) {
        case "scenario_start":
            return (
                <div className="flex items-center gap-3 py-2 px-4 bg-blue-50 rounded-lg border border-blue-200">
                    <Bot className="w-5 h-5 text-blue-600 flex-shrink-0" />
                    <div>
                        <div className="text-sm font-semibold text-blue-800">
                            🎬 场景开始：{data.title as string}
                        </div>
                        <div className="text-xs text-blue-600 mt-0.5">
                            {data.agent_persona as string}
                        </div>
                    </div>
                </div>
            );

        case "thinking":
            return (
                <div className="flex gap-3 py-2">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-purple-100 flex items-center justify-center">
                        <Brain className="w-4 h-4 text-purple-600" />
                    </div>
                    <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                            <Badge
                                variant="outline"
                                className="text-xs text-purple-600 border-purple-300"
                            >
                                Step {data.step as number} · Agent 思考
                            </Badge>
                        </div>
                        <div className="text-sm text-gray-700 bg-purple-50 rounded-lg p-3 border border-purple-100">
                            💭 {data.thought as string}
                        </div>
                    </div>
                </div>
            );

        case "tool_call":
            return (
                <div className="flex gap-3 py-1 pl-11">
                    <div className="flex-shrink-0 w-6 h-6 rounded-full bg-yellow-100 flex items-center justify-center">
                        <Wrench className="w-3 h-3 text-yellow-700" />
                    </div>
                    <div className="flex-1">
                        <div className="text-sm bg-yellow-50 rounded-lg p-3 border border-yellow-200">
                            <div className="flex items-center gap-2 text-yellow-800 font-semibold text-xs mb-1">
                                🔧 调用工具：
                                <code className="bg-yellow-200 px-2 py-0.5 rounded text-xs">
                                    {data.tool as string}
                                </code>
                            </div>
                            <pre className="text-xs text-gray-600 font-mono overflow-x-auto whitespace-pre-wrap">
                                {JSON.stringify(data.args, null, 2)}
                            </pre>
                        </div>
                    </div>
                </div>
            );

        case "firewall_result": {
            const decision = data.decision as string;
            const risk = data.risk_score as number;
            const isBlock = decision === "block";
            const breakdown = data.risk_breakdown as {
                tool_weight: number;
                arg_danger: number;
                frequency_penalty: number;
                details: string[];
            };

            return (
                <div className="flex gap-3 py-1 pl-11">
                    <div
                        className={`flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center ${
                            isBlock ? "bg-red-100" : "bg-green-100"
                        }`}
                    >
                        {isBlock ? (
                            <ShieldAlert className="w-3 h-3 text-red-600" />
                        ) : (
                            <ShieldCheck className="w-3 h-3 text-green-600" />
                        )}
                    </div>
                    <div className="flex-1">
                        <div
                            className={`rounded-lg p-3 border ${
                                isBlock
                                    ? "bg-red-50 border-red-200"
                                    : "bg-green-50 border-green-200"
                            }`}
                        >
                            <div className="flex items-center justify-between mb-2">
                                <div className="flex items-center gap-2">
                                    {isBlock ? (
                                        <Badge variant="destructive" className="text-xs">
                                            🛑 BLOCKED
                                        </Badge>
                                    ) : (
                                        <Badge
                                            variant="outline"
                                            className="text-xs border-green-400 text-green-700"
                                        >
                                            ✅ ALLOWED
                                        </Badge>
                                    )}
                                    <span className="text-xs text-gray-500">
                                        {data.reason as string}
                                    </span>
                                </div>
                                <span
                                    className={`font-mono font-bold text-sm ${riskColor(
                                        risk
                                    )}`}
                                >
                                    Risk: {risk.toFixed(0)}
                                </span>
                            </div>
                            {/* Risk breakdown bars */}
                            <div className="grid grid-cols-3 gap-3 text-xs">
                                <div>
                                    <div className="flex justify-between text-gray-500 mb-0.5">
                                        <span>工具权重</span>
                                        <span className="font-mono">
                                            {breakdown.tool_weight.toFixed(0)}/40
                                        </span>
                                    </div>
                                    <div className="w-full bg-gray-200 h-1.5 rounded">
                                        <div
                                            className="bg-blue-500 h-1.5 rounded transition-all"
                                            style={{
                                                width: `${(breakdown.tool_weight / 40) * 100}%`,
                                            }}
                                        />
                                    </div>
                                </div>
                                <div>
                                    <div className="flex justify-between text-gray-500 mb-0.5">
                                        <span>参数危险</span>
                                        <span className="font-mono">
                                            {breakdown.arg_danger.toFixed(0)}/40
                                        </span>
                                    </div>
                                    <div className="w-full bg-gray-200 h-1.5 rounded">
                                        <div
                                            className="bg-orange-500 h-1.5 rounded transition-all"
                                            style={{
                                                width: `${(breakdown.arg_danger / 40) * 100}%`,
                                            }}
                                        />
                                    </div>
                                </div>
                                <div>
                                    <div className="flex justify-between text-gray-500 mb-0.5">
                                        <span>频率惩罚</span>
                                        <span className="font-mono">
                                            {breakdown.frequency_penalty.toFixed(0)}/20
                                        </span>
                                    </div>
                                    <div className="w-full bg-gray-200 h-1.5 rounded">
                                        <div
                                            className="bg-purple-500 h-1.5 rounded transition-all"
                                            style={{
                                                width: `${(breakdown.frequency_penalty / 20) * 100}%`,
                                            }}
                                        />
                                    </div>
                                </div>
                            </div>
                            {breakdown.details.length > 0 && (
                                <div className="mt-2 pt-2 border-t border-gray-200">
                                    <div className="text-xs text-gray-400 mb-1">
                                        匹配详情：
                                    </div>
                                    <div className="flex flex-wrap gap-1">
                                        {breakdown.details.slice(0, 5).map((d, i) => (
                                            <span
                                                key={i}
                                                className="text-xs bg-white px-2 py-0.5 rounded border text-gray-600"
                                            >
                                                {d}
                                            </span>
                                        ))}
                                        {breakdown.details.length > 5 && (
                                            <span className="text-xs text-gray-400">
                                                +{breakdown.details.length - 5} more
                                            </span>
                                        )}
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            );
        }

        case "agent_reaction": {
            const isBlock = (data.decision as string) === "block";
            return (
                <div className="flex gap-3 py-1 pl-11">
                    <div
                        className={`flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center ${
                            isBlock ? "bg-red-50" : "bg-green-50"
                        }`}
                    >
                        <MessageSquare
                            className={`w-3 h-3 ${
                                isBlock ? "text-red-500" : "text-green-500"
                            }`}
                        />
                    </div>
                    <div
                        className={`text-sm rounded-lg px-3 py-2 border ${
                            isBlock
                                ? "bg-red-50/50 border-red-100 text-red-700"
                                : "bg-green-50/50 border-green-100 text-green-700"
                        }`}
                    >
                        {isBlock ? "🔄" : "👍"} {data.reaction as string}
                    </div>
                </div>
            );
        }

        case "scenario_end": {
            return (
                <div className="flex items-center gap-3 py-2 px-4 bg-green-50 rounded-lg border border-green-200 mt-2">
                    <ShieldCheck className="w-5 h-5 text-green-600 flex-shrink-0" />
                    <div className="text-sm font-semibold text-green-800">
                        🏁 场景结束 — 拦截 {data.blocked as number} 次，放行{" "}
                        {data.allowed as number} 次
                    </div>
                </div>
            );
        }

        default:
            return null;
    }
}
