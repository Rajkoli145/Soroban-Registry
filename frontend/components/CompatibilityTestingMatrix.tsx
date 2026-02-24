'use client';

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
    api,
    CompatibilityTestMatrixResponse,
    CompatibilityTestEntry,
    CompatibilityTestStatus,
    CompatibilityHistoryEntry,
} from '@/lib/api';
import {
    CheckCircle,
    XCircle,
    AlertTriangle,
    Clock,
    Play,
    History,
    Bell,
    Loader2,
    ChevronDown,
    ChevronUp,
} from 'lucide-react';

interface CompatibilityTestingMatrixProps {
    contractId: string;
}

function StatusBadge({ status }: { status: CompatibilityTestStatus }) {
    switch (status) {
        case 'compatible':
            return (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300">
                    <CheckCircle className="w-3 h-3" />
                    Compatible
                </span>
            );
        case 'warning':
            return (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300">
                    <AlertTriangle className="w-3 h-3" />
                    Warning
                </span>
            );
        case 'incompatible':
            return (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300">
                    <XCircle className="w-3 h-3" />
                    Incompatible
                </span>
            );
    }
}

function StatusCell({ entry }: { entry?: CompatibilityTestEntry }) {
    if (!entry) {
        return (
            <td className="px-3 py-2 text-center">
                <span className="text-gray-300 dark:text-gray-600">—</span>
            </td>
        );
    }

    const bgClass =
        entry.status === 'compatible'
            ? 'bg-green-50/40 dark:bg-green-900/10'
            : entry.status === 'warning'
              ? 'bg-amber-50/40 dark:bg-amber-900/10'
              : 'bg-red-50/40 dark:bg-red-900/10';

    return (
        <td className={`px-3 py-2 text-center ${bgClass}`}>
            <div className="flex flex-col items-center gap-1">
                <StatusBadge status={entry.status} />
                {entry.test_duration_ms != null && (
                    <span className="text-[10px] text-gray-400 dark:text-gray-500">
                        {entry.test_duration_ms}ms
                    </span>
                )}
            </div>
        </td>
    );
}

function SummaryCards({ summary }: { summary: CompatibilityTestMatrixResponse['summary'] }) {
    const cards = [
        {
            label: 'Total Tests',
            value: summary.total_tests,
            color: 'text-gray-900 dark:text-white',
            bg: 'bg-gray-50 dark:bg-gray-800/60',
        },
        {
            label: 'Compatible',
            value: summary.compatible_count,
            color: 'text-green-700 dark:text-green-400',
            bg: 'bg-green-50 dark:bg-green-900/20',
        },
        {
            label: 'Warnings',
            value: summary.warning_count,
            color: 'text-amber-700 dark:text-amber-400',
            bg: 'bg-amber-50 dark:bg-amber-900/20',
        },
        {
            label: 'Incompatible',
            value: summary.incompatible_count,
            color: 'text-red-700 dark:text-red-400',
            bg: 'bg-red-50 dark:bg-red-900/20',
        },
    ];

    return (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {cards.map((card) => (
                <div
                    key={card.label}
                    className={`${card.bg} rounded-lg px-4 py-3 text-center`}
                >
                    <div className={`text-2xl font-bold ${card.color}`}>{card.value}</div>
                    <div className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                        {card.label}
                    </div>
                </div>
            ))}
        </div>
    );
}

function HistoryTimeline({ changes }: { changes: CompatibilityHistoryEntry[] }) {
    if (changes.length === 0) {
        return (
            <p className="text-sm text-gray-400 dark:text-gray-500 text-center py-6">
                No compatibility changes recorded yet.
            </p>
        );
    }

    return (
        <div className="space-y-3 max-h-80 overflow-y-auto">
            {changes.map((change) => (
                <div
                    key={change.id}
                    className="flex items-start gap-3 text-sm border-l-2 border-gray-200 dark:border-gray-700 pl-3"
                >
                    <div className="flex-1">
                        <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-medium text-gray-900 dark:text-white">
                                SDK {change.sdk_version}
                            </span>
                            <span className="text-gray-400">·</span>
                            <span className="text-gray-500 dark:text-gray-400">
                                {change.wasm_runtime}
                            </span>
                            <span className="text-gray-400">·</span>
                            <span className="text-gray-500 dark:text-gray-400 capitalize">
                                {change.network}
                            </span>
                        </div>
                        <div className="flex items-center gap-2 mt-1">
                            {change.previous_status && (
                                <>
                                    <StatusBadge status={change.previous_status} />
                                    <span className="text-gray-400">→</span>
                                </>
                            )}
                            <StatusBadge status={change.new_status} />
                        </div>
                        {change.change_reason && (
                            <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">
                                {change.change_reason}
                            </p>
                        )}
                    </div>
                    <time className="text-xs text-gray-400 dark:text-gray-500 whitespace-nowrap">
                        {new Date(change.changed_at).toLocaleDateString()}
                    </time>
                </div>
            ))}
        </div>
    );
}

export default function CompatibilityTestingMatrix({ contractId }: CompatibilityTestingMatrixProps) {
    const queryClient = useQueryClient();
    const [showHistory, setShowHistory] = useState(false);
    const [showRunTest, setShowRunTest] = useState(false);
    const [testForm, setTestForm] = useState({
        sdk_version: '22.0.0',
        wasm_runtime: 'wasmtime-25.0',
        network: 'testnet',
    });

    const {
        data: matrix,
        isLoading,
        isError,
        error,
    } = useQuery({
        queryKey: ['compatibility-matrix', contractId],
        queryFn: () => api.getCompatibilityMatrix(contractId),
        enabled: !!contractId,
    });

    const { data: history } = useQuery({
        queryKey: ['compatibility-history', contractId],
        queryFn: () => api.getCompatibilityHistory(contractId, 20),
        enabled: !!contractId && showHistory,
    });

    const { data: notifications } = useQuery({
        queryKey: ['compatibility-notifications', contractId],
        queryFn: () => api.getCompatibilityNotifications(contractId),
        enabled: !!contractId,
    });

    const runTestMutation = useMutation({
        mutationFn: (data: { sdk_version: string; wasm_runtime: string; network: string }) =>
            api.runCompatibilityTest(contractId, data),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['compatibility-matrix', contractId] });
            queryClient.invalidateQueries({ queryKey: ['compatibility-history', contractId] });
            queryClient.invalidateQueries({ queryKey: ['compatibility-notifications', contractId] });
        },
    });

    const unreadCount = notifications?.filter((n) => !n.is_read).length ?? 0;

    if (isLoading) {
        return (
            <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-6">
                <div className="flex items-center justify-center py-12 gap-3 text-gray-400">
                    <Loader2 className="w-5 h-5 animate-spin" />
                    <span className="text-sm">Loading compatibility matrix…</span>
                </div>
            </div>
        );
    }

    if (isError) {
        return (
            <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-6">
                <p className="text-red-500 dark:text-red-400 text-sm text-center py-8">
                    {(error as Error)?.message ?? 'Failed to load compatibility data.'}
                </p>
            </div>
        );
    }

    if (!matrix) return null;

    // Build a lookup: sdk_version -> wasm_runtime -> network -> entry
    const lookup = new Map<string, CompatibilityTestEntry>();
    for (const entry of matrix.entries) {
        lookup.set(`${entry.sdk_version}|${entry.wasm_runtime}|${entry.network}`, entry);
    }

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between flex-wrap gap-3">
                <div>
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                        SDK Compatibility Matrix
                    </h3>
                    {matrix.last_tested && (
                        <p className="text-xs text-gray-400 dark:text-gray-500 mt-0.5 flex items-center gap-1">
                            <Clock className="w-3 h-3" />
                            Last tested {new Date(matrix.last_tested).toLocaleString()}
                        </p>
                    )}
                </div>
                <div className="flex items-center gap-2">
                    {unreadCount > 0 && (
                        <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300">
                            <Bell className="w-3 h-3" />
                            {unreadCount} alert{unreadCount > 1 ? 's' : ''}
                        </span>
                    )}
                    <button
                        onClick={() => setShowHistory(!showHistory)}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-750 transition-colors"
                    >
                        <History className="w-3.5 h-3.5" />
                        History
                        {showHistory ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                    </button>
                    <button
                        onClick={() => setShowRunTest(!showRunTest)}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium transition-colors"
                    >
                        <Play className="w-3.5 h-3.5" />
                        Run Test
                    </button>
                </div>
            </div>

            {/* Summary */}
            <SummaryCards summary={matrix.summary} />

            {/* Run Test Form */}
            {showRunTest && (
                <div className="rounded-xl border border-blue-200 dark:border-blue-800 bg-blue-50/50 dark:bg-blue-900/10 p-4">
                    <h4 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
                        Run Compatibility Test
                    </h4>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                        <div>
                            <label className="block text-xs text-gray-500 dark:text-gray-400 mb-1">
                                SDK Version
                            </label>
                            <input
                                type="text"
                                value={testForm.sdk_version}
                                onChange={(e) => setTestForm({ ...testForm, sdk_version: e.target.value })}
                                className="w-full px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm text-gray-900 dark:text-white"
                                placeholder="e.g. 22.0.0"
                            />
                        </div>
                        <div>
                            <label className="block text-xs text-gray-500 dark:text-gray-400 mb-1">
                                Wasm Runtime
                            </label>
                            <input
                                type="text"
                                value={testForm.wasm_runtime}
                                onChange={(e) => setTestForm({ ...testForm, wasm_runtime: e.target.value })}
                                className="w-full px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm text-gray-900 dark:text-white"
                                placeholder="e.g. wasmtime-25.0"
                            />
                        </div>
                        <div>
                            <label className="block text-xs text-gray-500 dark:text-gray-400 mb-1">
                                Network
                            </label>
                            <select
                                value={testForm.network}
                                onChange={(e) => setTestForm({ ...testForm, network: e.target.value })}
                                className="w-full px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-sm text-gray-900 dark:text-white"
                            >
                                <option value="mainnet">Mainnet</option>
                                <option value="testnet">Testnet</option>
                                <option value="futurenet">Futurenet</option>
                            </select>
                        </div>
                    </div>
                    <button
                        onClick={() => runTestMutation.mutate(testForm)}
                        disabled={runTestMutation.isPending}
                        className="mt-3 inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm font-medium transition-colors"
                    >
                        {runTestMutation.isPending ? (
                            <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        ) : (
                            <Play className="w-3.5 h-3.5" />
                        )}
                        {runTestMutation.isPending ? 'Testing…' : 'Run Test'}
                    </button>
                    {runTestMutation.isSuccess && (
                        <p className="text-xs text-green-600 dark:text-green-400 mt-2">
                            Test completed: {runTestMutation.data.status}
                        </p>
                    )}
                    {runTestMutation.isError && (
                        <p className="text-xs text-red-500 mt-2">
                            {(runTestMutation.error as Error)?.message ?? 'Test failed'}
                        </p>
                    )}
                </div>
            )}

            {/* Matrix Table */}
            {matrix.entries.length === 0 ? (
                <div className="text-center py-12 rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900">
                    <CheckCircle className="w-10 h-10 text-gray-300 dark:text-gray-600 mx-auto mb-3" />
                    <p className="text-gray-500 dark:text-gray-400 text-sm">
                        No compatibility tests recorded yet. Run a test to get started.
                    </p>
                </div>
            ) : (
                <div className="overflow-x-auto rounded-xl border border-gray-200 dark:border-gray-800">
                    <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700 text-sm">
                        <thead className="bg-gray-50 dark:bg-gray-800/60">
                            <tr>
                                <th className="sticky left-0 z-10 bg-gray-50 dark:bg-gray-800/60 px-3 py-3 text-left font-semibold text-gray-700 dark:text-gray-300 whitespace-nowrap border-r border-gray-200 dark:border-gray-700">
                                    SDK Version / Runtime
                                </th>
                                {matrix.networks.map((net) => (
                                    <th
                                        key={net}
                                        className="px-3 py-3 text-center font-semibold text-gray-700 dark:text-gray-300 whitespace-nowrap capitalize"
                                    >
                                        {net}
                                    </th>
                                ))}
                            </tr>
                        </thead>
                        <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-100 dark:divide-gray-800">
                            {matrix.sdk_versions.map((sdk) =>
                                matrix.wasm_runtimes.map((runtime) => (
                                    <tr
                                        key={`${sdk}|${runtime}`}
                                        className="hover:bg-gray-50 dark:hover:bg-gray-800/40 transition-colors"
                                    >
                                        <td className="sticky left-0 z-10 bg-white dark:bg-gray-900 px-3 py-2 border-r border-gray-100 dark:border-gray-800 whitespace-nowrap">
                                            <div className="font-medium text-gray-900 dark:text-white">
                                                <span className="inline-block px-1.5 py-0.5 rounded bg-blue-100 dark:bg-blue-900/40 text-blue-700 dark:text-blue-300 font-mono text-xs">
                                                    SDK {sdk}
                                                </span>
                                            </div>
                                            <div className="text-xs text-gray-400 font-mono mt-0.5">
                                                {runtime}
                                            </div>
                                        </td>
                                        {matrix.networks.map((net) => {
                                            const entry = lookup.get(`${sdk}|${runtime}|${net}`);
                                            return <StatusCell key={net} entry={entry} />;
                                        })}
                                    </tr>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>
            )}

            {/* History Panel */}
            {showHistory && (
                <div className="rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 p-4">
                    <h4 className="text-sm font-semibold text-gray-900 dark:text-white mb-3 flex items-center gap-2">
                        <History className="w-4 h-4" />
                        Compatibility History
                    </h4>
                    {history ? (
                        <HistoryTimeline changes={history.changes} />
                    ) : (
                        <div className="flex items-center justify-center py-6 text-gray-400">
                            <Loader2 className="w-4 h-4 animate-spin mr-2" />
                            Loading history…
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}
