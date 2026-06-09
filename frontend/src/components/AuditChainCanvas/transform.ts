import { MarkerType } from '@xyflow/react';
import ELK from 'elkjs/lib/elk.bundled.js';
import type {
  AuditChainRawEdge,
  AuditChainRawGraph,
  AuditChainRawNode,
} from '@/types/auditSessionDetail';
import {
  asEdgeKind,
  asNodeLabel,
  EDGE_COLOR,
  NODE_HEIGHT,
  NODE_WIDTH,
  type RunStatus,
} from './constants';
import type {
  AuditFlowEdge,
  AuditFlowEdgeData,
  AuditFlowNode,
  AuditFlowNodeData,
} from './types';

const elk = new ELK();

function pickTitle(node: AuditChainRawNode): string {
  const label = asNodeLabel(node.labels);
  const p = node.props || {};
  switch (label) {
    case 'Task':
      return String(p.name ?? '审计任务');
    case 'AuditStage':
      return String(p.name ?? '审计阶段');
    case 'Language':
      return String(p.name ?? 'Language');
    case 'RiskCategory':
      return String(p.category_name ?? '风险类别');
    case 'SinkFlowNode':
      return p.function ? `${p.function}()` : 'Sink 节点';
    case 'ChainNode':
      return p.function ? `${p.function}()` : '调用链节点';
    case 'Knowledge':
      return '知识库';
    case 'AuditInfo':
      return String(
        p.title ?? p.summary ?? p.name ?? p.message ?? '审计信息',
      ).slice(0, 80);
    case 'AnalysisResult':
      return String(p.vul_name ?? '分析结果');
    default:
      return node.labels[0] ?? '未知节点';
  }
}

function pickSubtitle(node: AuditChainRawNode): string | undefined {
  const p = node.props || {};
  const label = asNodeLabel(node.labels);

  // 时间戳格式化（只显示时分秒）
  const fmtTime = (ts: string | undefined) => {
    if (!ts) return null;
    try {
      const d = new Date(ts);
      if (isNaN(d.getTime())) return null;
      return `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}:${d.getSeconds().toString().padStart(2, '0')}`;
    } catch { return null; }
  };

  switch (label) {
    case 'SinkFlowNode':
    case 'ChainNode':
      if (p.file && p.line != null) {
        return `${p.file}:${p.line}`;
      }
      return p.file ? String(p.file) : undefined;
    case 'RiskCategory':
      return `优先级 ${p.level ?? '-'}`;
    case 'AnalysisResult':
      if (p.cwe != null && p.cwe !== '')
        return `CWE-${String(p.cwe).replace(/^CWE-?/i, '')}`;
      if (p.cwe_id != null && p.cwe_id !== '') return String(p.cwe_id);
      return undefined;
    case 'Language':
      return `优先级 ${p.level ?? '-'}`;
    case 'AuditStage': {
      // 显示状态 + 时间范围
      const status = p.status ?? '';
      const start = fmtTime(p.created_at);
      const end = fmtTime(p.end_time);
      const statusColor = status === 'completed' ? '✓' : status === 'running' ? '⟳' : status === 'failed' ? '✗' : '○';
      if (start && end) return `${statusColor} ${start} → ${end}`;
      if (start) return `${statusColor} ${start}`;
      return status ? `${statusColor} ${status}` : undefined;
    }
    case 'AuditInfo': {
      const kind = p.kind ?? p.info_type ?? p.category;
      const src = p.source ?? p.origin;
      const parts = [kind, src]
        .filter((v) => v !== undefined && v !== null && v !== '')
        .map((v) => String(v));
      return parts.length > 0 ? parts.join(' · ') : undefined;
    }
    case 'Task': {
      const projectId = p.project_id;
      return projectId
        ? `Project ${String(projectId).slice(0, 8)}…`
        : undefined;
    }
    default:
      return undefined;
  }
}

function pickStatus(node: AuditChainRawNode): RunStatus | undefined {
  const s = node.props?.status;
  if (
    s === 'completed' ||
    s === 'running' ||
    s === 'pending' ||
    s === 'failed'
  ) {
    return s;
  }
  return undefined;
}

/** 思维链画布不展示的节点类型（仍可通过桥接边保持上下游连通） */
const EXCLUDED_GRAPH_LABELS = new Set(['AuditInfo']);

function bridgeEdgesAroundExcluded(
  rawEdges: AuditChainRawEdge[],
  excludedIds: Set<string>,
  visibleNodeIds: Set<string>,
): AuditChainRawEdge[] {
  const direct = rawEdges.filter(
    (e) => visibleNodeIds.has(e.start) && visibleNodeIds.has(e.end),
  );
  const edgeKey = (e: AuditChainRawEdge) => `${e.start}\t${e.end}\t${e.type}`;
  const seen = new Set(direct.map(edgeKey));
  const bridged: AuditChainRawEdge[] = [];

  for (const mid of excludedIds) {
    const incoming = rawEdges.filter((e) => e.end === mid);
    const outgoing = rawEdges.filter((e) => e.start === mid);
    for (const inE of incoming) {
      if (!visibleNodeIds.has(inE.start)) continue;
      for (const outE of outgoing) {
        if (!visibleNodeIds.has(outE.end)) continue;
        const candidate: AuditChainRawEdge = {
          elementId: `bridge:${inE.start}:${outE.end}:${outE.type}`,
          type: outE.type,
          start: inE.start,
          end: outE.end,
          props: {},
        };
        const key = edgeKey(candidate);
        if (seen.has(key)) continue;
        seen.add(key);
        bridged.push(candidate);
      }
    }
  }

  return [...direct, ...bridged];
}

export function buildGraph(raw: AuditChainRawGraph): {
  rfNodes: AuditFlowNode[];
  rfEdges: AuditFlowEdge[];
} {
  const supportedNodes = raw.nodes.filter((n) => {
    const label = asNodeLabel(n.labels);
    return label !== null && !EXCLUDED_GRAPH_LABELS.has(label);
  });
  const nodeIds = new Set(supportedNodes.map((n) => n.elementId));
  const excludedIds = new Set(
    raw.nodes
      .filter((n) => asNodeLabel(n.labels) === 'AuditInfo')
      .map((n) => n.elementId),
  );
  const graphEdges = bridgeEdgesAroundExcluded(raw.edges, excludedIds, nodeIds);

  const rfNodes: AuditFlowNode[] = supportedNodes.map((n) => {
    const label = asNodeLabel(n.labels);
    const data: AuditFlowNodeData = {
      label: label ?? 'Task',
      title: pickTitle(n),
      subtitle: pickSubtitle(n),
      status: pickStatus(n),
      raw: n.props ?? {},
    };
    return {
      id: n.elementId,
      type: 'audit',
      position: { x: 0, y: 0 },
      data,
      width: NODE_WIDTH,
      height: NODE_HEIGHT,
    };
  });

  const rfEdges: AuditFlowEdge[] = graphEdges.map((e: AuditChainRawEdge) => {
    const kind = asEdgeKind(e.type);
    const data: AuditFlowEdgeData = { kind };
    return {
      id: e.elementId,
      source: e.start,
      target: e.end,
      type: 'audit',
      data,
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: EDGE_COLOR[kind] ?? '#94a3b8',
        width: 14,
        height: 14,
      },
      style: {
        stroke: EDGE_COLOR[kind] ?? '#94a3b8',
        strokeWidth: 1.5,
      },
    };
  });

  return { rfNodes, rfEdges };
}

export async function layoutGraph(
  nodes: AuditFlowNode[],
  edges: AuditFlowEdge[],
): Promise<{ nodes: AuditFlowNode[]; edges: AuditFlowEdge[] }> {
  if (nodes.length === 0) {
    return { nodes, edges };
  }
  const elkGraph = {
    id: 'root',
    layoutOptions: {
      'elk.algorithm': 'layered',
      'elk.direction': 'RIGHT',
      'elk.layered.spacing.nodeNodeBetweenLayers': '110',
      'elk.spacing.nodeNode': '40',
      'elk.layered.nodePlacement.strategy': 'NETWORK_SIMPLEX',
      'elk.layered.crossingMinimization.semiInteractive': 'true',
      'elk.edgeRouting': 'ORTHOGONAL',
      'elk.padding': '[top=40,left=40,bottom=40,right=40]',
    },
    children: nodes.map((n) => ({
      id: n.id,
      width: n.width ?? NODE_WIDTH,
      height: n.height ?? NODE_HEIGHT,
    })),
    edges: edges.map((e) => ({
      id: e.id,
      sources: [e.source],
      targets: [e.target],
    })),
  };

  const laid = await elk.layout(elkGraph as any);
  const positions = new Map<string, { x: number; y: number }>();
  for (const c of laid.children ?? []) {
    if (!c.id) continue;
    positions.set(c.id, { x: c.x ?? 0, y: c.y ?? 0 });
  }

  return {
    nodes: nodes.map((n) => ({
      ...n,
      position: positions.get(n.id) ?? { x: 0, y: 0 },
    })),
    edges,
  };
}
