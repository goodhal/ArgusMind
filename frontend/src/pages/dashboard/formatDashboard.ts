import { formatTokenCount } from '@/utils/formatTokenCount';

const FINDING_CATEGORY_LABELS: Record<string, string> = {
  sql_injection: 'SQL 注入',
  nosql_injection: 'NoSQL 注入',
  xss: 'XSS',
  csrf: 'CSRF',
  ssrf: 'SSRF',
  rce: '远程代码执行',
  command_execution: '命令执行',
  command_injection: '命令注入',
  code_injection: '代码注入',
  expression_injection: '表达式注入',
  ssti: '模板注入',
  file_upload: '文件上传',
  file_read: '文件读取',
  file_write: '文件写入',
  archive_extract: '归档解压',
  path_traversal: '路径遍历',
  info_leak: '信息泄露',
  information_disclosure: '信息泄露',
  authentication: '认证缺陷',
  authorization: '授权缺陷',
  deserialization: '反序列化',
  xxe: 'XXE',
  ldap_injection: 'LDAP 注入',
  xpath_injection: 'XPath 注入',
  open_redirect: '开放重定向',
  crlf_injection: 'CRLF 注入',
  weak_crypto: '弱加密',
  weak_hash: '弱哈希',
  predictable_random: '可预测随机',
  misconfiguration: '配置错误',
  cors_misconfiguration: 'CORS 配置错误',
  component_vulnerability: '组件漏洞',
  business_logic: '业务逻辑',
};

const FINDING_SEVERITY_LABELS: Record<string, string> = {
  critical: '严重',
  high: '高',
  medium: '中',
  low: '低',
  info: '信息',
  unknown: '未分级',
};

/** 漏洞严重等级展示名 */
export function formatFindingSeverity(severity?: string | null): string {
  const key = severity?.trim().toLowerCase();
  if (!key) return '—';
  return FINDING_SEVERITY_LABELS[key] ?? severity!;
}

/** 漏洞分类展示名（兼容 snake_case / 未分类） */
export function formatFindingCategory(name?: string | null): string {
  const raw = name?.trim();
  if (!raw || raw === '未分类') return '未分类';
  const key = raw.toLowerCase();
  if (FINDING_CATEGORY_LABELS[key]) return FINDING_CATEGORY_LABELS[key];
  if (/^[\u4e00-\u9fa5]/.test(raw)) return raw;
  return raw
    .split('_')
    .filter(Boolean)
    .map((part) => {
      const lower = part.toLowerCase();
      if (lower === 'sql') return 'SQL';
      if (lower === 'xss') return 'XSS';
      if (lower === 'csrf') return 'CSRF';
      if (lower === 'api') return 'API';
      return lower.charAt(0).toUpperCase() + lower.slice(1);
    })
    .join(' ');
}

export function formatLineCount(value: number): string {
  if (!Number.isFinite(value)) return '—';
  const n = Math.round(value);
  if (n >= 1_000_000) {
    const m = n / 1_000_000;
    return `${m % 1 === 0 ? m.toFixed(0) : m.toFixed(1)}M`;
  }
  if (n >= 1_000) {
    const k = n / 1_000;
    return `${k % 1 === 0 ? k.toFixed(0) : k.toFixed(1)}K`;
  }
  return String(n);
}

export function formatKpiValue(
  value: number,
  valueType?: 'number' | 'percent' | 'token' | 'lines',
): string {
  switch (valueType) {
    case 'percent':
      return `${value.toFixed(1)}%`;
    case 'token':
      return formatTokenCount(value);
    case 'lines':
      return formatLineCount(value);
    default:
      return value.toLocaleString('zh-CN');
  }
}

export function formatDuration(seconds?: number | null): string {
  if (seconds == null || !Number.isFinite(seconds) || seconds < 0) {
    return '—';
  }
  const s = Math.floor(seconds);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  const pad = (n: number) => String(n).padStart(2, '0');
  if (h > 0) return `${pad(h)}:${pad(m)}:${pad(sec)}`;
  return `${pad(m)}:${pad(sec)}`;
}

export function formatTrendText(trend: {
  value: number;
  direction: 'up' | 'down';
  suffix?: string;
}): string {
  const arrow = trend.direction === 'up' ? '↑' : '↓';
  const suffix = trend.suffix ?? '';
  const abs = Math.abs(trend.value);
  const num =
    suffix === '%'
      ? `${abs.toFixed(1)}%`
      : abs >= 1_000_000
        ? formatTokenCount(abs)
        : abs >= 1_000
          ? formatLineCount(abs)
          : String(abs);
  const sign = trend.direction === 'up' ? '+' : '-';
  if (abs === 0) return '较昨日 持平';
  return `较昨日 ${sign}${num}${suffix && suffix !== '%' ? suffix : ''} ${arrow}`;
}
