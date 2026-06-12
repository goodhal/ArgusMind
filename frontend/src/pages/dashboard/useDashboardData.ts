import { useCallback, useEffect, useRef, useState } from 'react';
import type { DashboardSummary } from '@/services/dashboard';
import {
  type DailySeverityStatRaw,
  type DailyTokenStatRaw,
  type FindingTypeStatRaw,
  getFindingStats,
  getFindingStatsByType,
  getFindingStatsDaily,
  getProjectOverview,
  getTaskStats,
  getTokenStats,
  getTokenTrend,
  unwrapListData,
  unwrapOkData,
} from '@/services/dashboardApi';
import {
  getProjectListStats,
  listProjects,
  type ProjectListItem,
} from '@/services/projects';
import { listTasksApiTasksGet } from '@/services/swagger/tasks';
import {
  type BuildDashboardInput,
  buildDashboardView,
} from './buildDashboardView';
import {
  type DashboardTrendRangeKey,
  DEFAULT_TREND_RANGE,
  trendRangeToDays,
} from './dashboardTrendRange';

const EMPTY_TASK_STATS = { total: 0, by_status: {} };
const EMPTY_OVERVIEW = {
  total_projects: 0,
  total_files: 0,
  total_lines: 0,
  languages: [],
  top_by_vulnerabilities: [],
};
const EMPTY_FINDING_STATS = { total: 0, by_severity: {} };
const EMPTY_TOKEN_STATS = {
  llm_input: 0,
  llm_output: 0,
  code_agent_input: 0,
  code_agent_output: 0,
  total: 0,
};

type DashboardBaseInput = Omit<
  BuildDashboardInput,
  'findingDaily' | 'tokenTrend' | 'trendDays'
>;

async function fetchTrendSeries(days: number): Promise<{
  findingDaily: DailySeverityStatRaw[];
  tokenTrend: DailyTokenStatRaw[];
}> {
  const results = await Promise.allSettled([
    getFindingStatsDaily(days),
    getTokenTrend(days),
  ]);

  const pickList = (index: number): unknown[] => {
    const item = results[index];
    if (item?.status === 'fulfilled') {
      return unwrapListData(item.value);
    }
    return [];
  };

  return {
    findingDaily: pickList(0) as DailySeverityStatRaw[],
    tokenTrend: pickList(1) as DailyTokenStatRaw[],
  };
}

async function fetchDashboardBase(): Promise<DashboardBaseInput> {
  const results = await Promise.allSettled([
    getTaskStats(),
    getProjectOverview(),
    getFindingStats(),
    getFindingStatsByType(5),
    getTokenStats(),
    getProjectListStats().catch(() => null),
    listTasksApiTasksGet({ current: 1, pageSize: 10 }),
    listProjects({ current: 1, pageSize: 200 }),
  ]);

  const pick = <T>(index: number, fallback: T, parse: (v: unknown) => T): T => {
    const item = results[index];
    if (item?.status === 'fulfilled') {
      try {
        return parse(item.value);
      } catch (e) {
        return fallback;
      }
    }
    return fallback;
  };

  const projectsRes =
    results[7]?.status === 'fulfilled' ? results[7].value : null;
  const projectList = unwrapListData<ProjectListItem>(projectsRes);
  const projectMap = new Map(projectList.map((p) => [p.id, p] as const));

  const projectStats =
    results[5]?.status === 'fulfilled' ? results[5].value : null;

  return {
    taskStats: pick(0, EMPTY_TASK_STATS, (v) =>
      unwrapOkData(v, EMPTY_TASK_STATS),
    ),
    projectOverview: pick(1, EMPTY_OVERVIEW, (v) =>
      unwrapOkData(v, EMPTY_OVERVIEW),
    ),
    findingStats: pick(2, EMPTY_FINDING_STATS, (v) =>
      unwrapOkData(v, EMPTY_FINDING_STATS),
    ),
    findingByType: pick(3, [], (v) => unwrapListData<FindingTypeStatRaw>(v)),
    tokenStats: pick(4, EMPTY_TOKEN_STATS, (v) =>
      unwrapOkData(v, EMPTY_TOKEN_STATS),
    ),
    projectListStats:
      projectStats && typeof projectStats === 'object'
        ? (projectStats as { total: number; pendingScan: number })
        : null,
    recentTasks: pick(6, [], (v) => unwrapListData(v)),
    projectMap,
  };
}

function mergeDashboard(
  base: DashboardBaseInput,
  findingDaily: DailySeverityStatRaw[],
  tokenTrend: DailyTokenStatRaw[],
  trendDays: number,
): DashboardSummary {
  return buildDashboardView({
    ...base,
    findingDaily,
    tokenTrend,
    trendDays,
  });
}

export function useDashboardData() {
  const [data, setData] = useState<DashboardSummary | undefined>();
  const [loading, setLoading] = useState(true);
  const [trendLoading, setTrendLoading] = useState(false);
  const [error, setError] = useState<Error | undefined>();
  const [trendRange, setTrendRangeState] =
    useState<DashboardTrendRangeKey>(DEFAULT_TREND_RANGE);
  const trendRangeRef = useRef<DashboardTrendRangeKey>(DEFAULT_TREND_RANGE);
  const baseRef = useRef<DashboardBaseInput | null>(null);

  trendRangeRef.current = trendRange;

  const loadTrend = useCallback(
    async (range: DashboardTrendRangeKey, base: DashboardBaseInput) => {
      const days = trendRangeToDays(range);
      const { findingDaily, tokenTrend } = await fetchTrendSeries(days);
      return mergeDashboard(base, findingDaily, tokenTrend, days);
    },
    [],
  );

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(undefined);
    const days = trendRangeToDays(trendRangeRef.current);
    try {
      const [base, trends] = await Promise.all([
        fetchDashboardBase(),
        fetchTrendSeries(days),
      ]);
      baseRef.current = base;
      setData(
        mergeDashboard(base, trends.findingDaily, trends.tokenTrend, days),
      );
    } catch (e) {
      setError(e instanceof Error ? e : new Error('仪表盘数据加载失败'));
    } finally {
      setLoading(false);
    }
  }, []);

  const changeTrendRange = useCallback(
    async (range: DashboardTrendRangeKey) => {
      setTrendRangeState(range);
      trendRangeRef.current = range;
      const base = baseRef.current;
      if (!base) return;
      setTrendLoading(true);
      try {
        const summary = await loadTrend(range, base);
        setData(summary);
      } catch {
        // 趋势加载失败静默处理
      } finally {
        setTrendLoading(false);
      }
    },
    [loadTrend],
  );

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return {
    data,
    loading,
    trendLoading,
    error,
    refresh,
    trendRange,
    setTrendRange: changeTrendRange,
  };
}
