import {
  CompressOutlined,
  ExpandOutlined,
  FullscreenExitOutlined,
  FullscreenOutlined,
  LinkOutlined,
} from '@ant-design/icons';
import { PageContainer } from '@ant-design/pro-components';
import { history, useParams } from '@umijs/max';
import { Button, Card, Empty, message, Space, Spin, Tabs } from 'antd';
import React, {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import AuditChainCanvas, {
  type AuditChainFocusNodeRequest,
} from '@/components/AuditChainCanvas';
import {
  auditChainGraphFingerprint,
  fetchAuditChainGraph,
  getAuditSessionDetail,
  listTaskEventsOlder,
  mergeAuditSessionDetailDelta,
  mergeOlderTaskEventsIntoDetail,
  type TaskEventListMeta,
} from '@/services/auditSessions';
import {
  getEventApiEventsEventIdGet,
  getHumanApprovalApiEventsHumanApprovalsInteractionIdGet,
  listEventOpencodeEventsApiEventsEventIdOpencodeGet,
  resolveHumanApprovalApiEventsHumanApprovalsInteractionIdPost,
} from '@/services/swagger/events';
import {
  retryTaskApiTasksTaskIdRetryGet,
} from '@/services/swagger/tasks';
import {
  getReportApiReportsTaskIdGet,
  downloadHtmlReportApiReportsTaskIdHtmlGet,
  regenerateHtmlReportApiReportsTaskIdRegeneratePost,
} from '@/services/swagger/reports';
import type { AuditSessionDetailDTO } from '@/types/auditSessionDetail';
import {
  buildOpencodeStreamTimeline,
  mergeOpencodeRowsById,
} from '@/utils/opencodeEventsMerge';
import { utcApiStringToEpochMs } from '@/utils/utcDateTimeDisplay';
import { buildTaskDetailModuleTabs, type QuickScanData } from './buildTaskDetailModuleTabs';
import {
  OPENCODE_STREAM_MIN_HEIGHT,
  OPENCODE_STREAM_VIEWPORT_BOTTOM_GAP,
  TASK_DETAIL_AUDIT_CHAIN_TRAY_CLASS,
  TASK_DETAIL_AUDIT_CHAIN_TRAY_PADDING,
  TASK_DETAIL_MAIN_COLUMNS_HEIGHT,
  TASK_DETAIL_MODULE_TABS_CLASS,
} from './detailStyles';
import { ensureTaskDetailPageStylesMounted } from './ensureTaskDetailPageStyles';
import { PlanApprovalModal } from './PlanApprovalModal';
import {
  type HumanApprovalPayload,
  makeLanguageGroupId,
  type PlanRow,
  parsePlanRowsFromMessage,
  serializePlanRowsToMessage,
} from './planModel';
import { TaskEventDetailDrawer } from './TaskEventDetailDrawer';
import { applyRunningDisplayedEventRefreshes } from './taskEventListRunningRefresh';
import { useTaskCompletionStatus } from './useTaskCompletionStatus';

const TaskDetailPage: React.FC = () => {
  const { id: taskId } = useParams<{ id: string }>();
  const [loading, setLoading] = useState(true);
  const [detail, setDetail] = useState<AuditSessionDetailDTO | null>(null);
  const [eventListMeta, setEventListMeta] = useState<TaskEventListMeta | null>(
    null,
  );
  const [loadingOlderEvents, setLoadingOlderEvents] = useState(false);
  const [eventDrawerOpen, setEventDrawerOpen] = useState(false);
  const [eventDetailLoading, setEventDetailLoading] = useState(false);
  const [selectedEventId, setSelectedEventId] = useState<string>('');
  const [selectedEventDetail, setSelectedEventDetail] =
    useState<API.EventRead | null>(null);
  const [opencodeRows, setOpencodeRows] = useState<API.OpencodeEventRead[]>([]);
  const [opencodeLoading, setOpencodeLoading] = useState(false);
  const opencodeRowsRef = useRef<API.OpencodeEventRead[]>([]);
  const opencodeStreamScrollRef = useRef<HTMLDivElement | null>(null);
  const [opencodeStreamMaxHeightPx, setOpencodeStreamMaxHeightPx] = useState<
    number | null
  >(null);
  const [planModalOpen, setPlanModalOpen] = useState(false);
  const [planModalLoading, setPlanModalLoading] = useState(false);
  const [planRows, setPlanRows] = useState<PlanRow[]>([]);
  const [planInteractionId, setPlanInteractionId] = useState('');
  const [planEventId, setPlanEventId] = useState('');
  const [handledInteractionIds, setHandledInteractionIds] = useState<string[]>(
    [],
  );
  const [humanApprovalMetaMap, setHumanApprovalMetaMap] = useState<
    Record<string, HumanApprovalPayload>
  >({});
  const [planCreatedAt, setPlanCreatedAt] = useState<string>('');
  const [planTimeoutSeconds, setPlanTimeoutSeconds] = useState<number>(0);
  const [countdownNow, setCountdownNow] = useState(Date.now());
  /** 在任务详情页主内容区内铺满审计链路（非浏览器全屏） */
  const [auditChainPageExpand, setAuditChainPageExpand] = useState(false);
  const [auditChainBrowserFullscreen, setAuditChainBrowserFullscreen] =
    useState(false);
  const [quickScanData, setQuickScanData] = useState<QuickScanData | null>(null);
  const auditChainTrayRef = useRef<HTMLDivElement | null>(null);

  const detailRef = useRef<AuditSessionDetailDTO | null>(null);
  const reloadCompletionRef = useRef<
    ((options?: { silent?: boolean }) => Promise<void>) | null
  >(null);
  useEffect(() => {
    detailRef.current = detail;
  }, [detail]);

  const toggleAuditChainPageExpand = useCallback(() => {
    setAuditChainPageExpand((v) => !v);
  }, []);

  useEffect(() => {
    const onFullscreenChange = () => {
      const el = auditChainTrayRef.current;
      setAuditChainBrowserFullscreen(
        Boolean(el && document.fullscreenElement === el),
      );
      requestAnimationFrame(() => {
        window.dispatchEvent(new Event('resize'));
      });
    };
    document.addEventListener('fullscreenchange', onFullscreenChange);
    return () =>
      document.removeEventListener('fullscreenchange', onFullscreenChange);
  }, []);

  const toggleAuditChainBrowserFullscreen = useCallback(async () => {
    const el = auditChainTrayRef.current;
    if (!el) return;
    try {
      if (document.fullscreenElement === el) {
        await document.exitFullscreen();
      } else {
        await el.requestFullscreen();
      }
    } catch {
      message.error('无法进入全屏，请检查浏览器权限');
    }
  }, []);

  useEffect(() => {
    const el = auditChainTrayRef.current;
    if (el && document.fullscreenElement === el) {
      void document.exitFullscreen();
    }
    setAuditChainBrowserFullscreen(false);
  }, [taskId]);

  /**
   * 审计链路图指纹。
   *
   * 仅在轮询拉到新事件 → 重新拉图 → 指纹不同时才更新 `auditChainGraph`，
   * 否则保持上一次的引用不变，避免画布做任何重布局或重渲染。
   */
  const auditChainGraphFingerprintRef = useRef<string>('');

  const load = useCallback(
    async (options?: { silent?: boolean }) => {
      const silent = Boolean(options?.silent);
      if (!taskId) {
        setDetail(null);
        setEventListMeta(null);
        setLoading(false);
        auditChainGraphFingerprintRef.current = '';
        return;
      }
      if (!silent) {
        setEventListMeta(null);
      }
      if (!silent) {
        setLoading(true);
      }
      let afterEventId: number | undefined;
      if (silent && detailRef.current?.events?.length) {
        const ids = detailRef.current.events
          .map((e) => Number(e.id))
          .filter((n) => Number.isFinite(n));
        if (ids.length > 0) {
          afterEventId = Math.max(...ids);
        }
      }
      let mergedForRunningPoll: AuditSessionDetailDTO | null = null;
      let eventListUpdated = false;
      try {
        const sessionRes = await getAuditSessionDetail(
          taskId,
          afterEventId !== undefined ? { afterEventId } : undefined,
        );
        if (sessionRes.success && sessionRes.data) {
          if (sessionRes.partialEvents) {
            const hasNewEvents = sessionRes.data.events.length > 0;
            if (hasNewEvents) {
              eventListUpdated = true;
            }
            // 仅在「确实有新事件」时才尝试刷新审计链路图，避免无谓的请求
            let nextGraphOverride:
              | AuditSessionDetailDTO['auditChainGraph']
              | undefined;
            if (hasNewEvents) {
              const newGraph = await fetchAuditChainGraph(taskId);
              const newFingerprint = auditChainGraphFingerprint(newGraph);
              if (newFingerprint !== auditChainGraphFingerprintRef.current) {
                auditChainGraphFingerprintRef.current = newFingerprint;
                nextGraphOverride = newGraph;
              }
            }

            let merged = detailRef.current
              ? mergeAuditSessionDetailDelta(detailRef.current, sessionRes.data)
              : sessionRes.data;
            // 指纹未变 → 保留 merge 已经做的 `prev.auditChainGraph` 引用
            if (nextGraphOverride !== undefined) {
              merged = { ...merged, auditChainGraph: nextGraphOverride };
            }
            mergedForRunningPoll = merged;
            setDetail(merged);
          } else {
            auditChainGraphFingerprintRef.current = auditChainGraphFingerprint(
              sessionRes.data.auditChainGraph,
            );
            mergedForRunningPoll = sessionRes.data;
            setDetail(sessionRes.data);
            if (sessionRes.eventListMeta) {
              setEventListMeta(sessionRes.eventListMeta);
            }
          }
        } else {
          setDetail(null);
          setEventListMeta(null);
          auditChainGraphFingerprintRef.current = '';
          if (!silent) {
            message.error('加载任务详情失败');
          }
        }
      } catch {
        setDetail(null);
        setEventListMeta(null);
        auditChainGraphFingerprintRef.current = '';
        if (!silent) {
          message.error('加载任务详情失败');
        }
      } finally {
        if (!silent) {
          setLoading(false);
        }
      }
      if (silent && mergedForRunningPoll) {
        const patched = await applyRunningDisplayedEventRefreshes(
          taskId,
          mergedForRunningPoll,
          setDetail,
        );
        if (patched) {
          eventListUpdated = true;
        }
      }
      if (silent && eventListUpdated) {
        void reloadCompletionRef.current?.({ silent: true });
      }
    },
    [taskId],
  );

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (!taskId) return;
    const timerId = window.setInterval(() => {
      void load({ silent: true });
    }, 10_000);
    return () => window.clearInterval(timerId);
  }, [taskId, load]);

  useEffect(() => {
    const timer = window.setInterval(() => setCountdownNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  const auditChainGraph = detail?.auditChainGraph ?? null;

  /**
   * 仅在「任务切换」时变化，用于在画布内重置选中态 / 过滤态 / fit-view。
   * 节点 / 边数量变化由画布的 `raw` 引用驱动局部更新，不影响该 key。
   */
  const graphKey = useMemo(
    () => (detail ? `${taskId}-${detail.session.id}` : (taskId ?? '')),
    [detail, taskId],
  );

  /** 在审计链路图中定位节点（由 vulnerability 事件卡片等触发） */
  const [auditChainFocusRequest, setAuditChainFocusRequest] =
    useState<AuditChainFocusNodeRequest | null>(null);

  const handleRequestFocusAuditChainNode = useCallback(
    (neo4jElementId: string) => {
      const elementId = neo4jElementId.trim();
      if (!elementId) {
        message.warning('缺少图谱节点 ID');
        return;
      }
      setAuditChainFocusRequest({
        elementId,
        nonce: Date.now(),
      });
    },
    [],
  );

  useEffect(() => {
    setAuditChainFocusRequest(null);
  }, [graphKey]);

  const sortedEvents = useMemo(() => {
    if (!detail) return [];
    const next = detail.events.filter(
      (e) => (e.actionType || '').trim().length > 0,
    );
    next.sort(
      (a, b) =>
        (utcApiStringToEpochMs(a.startedAt) ?? 0) -
        (utcApiStringToEpochMs(b.startedAt) ?? 0),
    );
    return next;
  }, [detail]);

  const missingHumanApprovalInteractionIds = useMemo(() => {
    if (!detail) return [];
    return Array.from(
      new Set(
        detail.events
          .filter(
            (e) => (e.actionType || '').toLowerCase() === 'human_approval',
          )
          .map((e) => (e.reason || '').trim())
          .filter(
            (id): id is string => Boolean(id) && !humanApprovalMetaMap[id],
          ),
      ),
    );
  }, [detail, humanApprovalMetaMap]);

  useEffect(() => {
    opencodeRowsRef.current = opencodeRows;
  }, [opencodeRows]);

  const opencodeStreamItems = useMemo(
    () => buildOpencodeStreamTimeline(opencodeRows),
    [opencodeRows],
  );

  const isCodeAgentEventDetail = useMemo(() => {
    const name = (selectedEventDetail?.tool_name || '').trim().toLowerCase();
    return name === 'code_agent';
  }, [selectedEventDetail?.tool_name]);

  const isEventStatusFinished = useCallback((status?: string | null) => {
    const s = (status || '').trim().toLowerCase();
    if (!s) return false;
    return (
      s === 'completed' ||
      s === 'success' ||
      s === 'succeeded' ||
      s === 'failed' ||
      s === 'error' ||
      s === 'cancelled' ||
      s === 'canceled' ||
      s === 'timeout' ||
      s === 'aborted'
    );
  }, []);

  /** 实时事件状态：优先看主列表（每 10s 刷新），回落到首次抽屉详情 */
  const selectedEventFinished = useMemo(() => {
    if (!selectedEventId) return false;
    const liveEvent = detail?.events.find((e) => e.id === selectedEventId);
    if (liveEvent) {
      return (
        isEventStatusFinished(liveEvent.finalStatus) ||
        isEventStatusFinished(liveEvent.status)
      );
    }
    if (selectedEventDetail) {
      return (
        isEventStatusFinished(selectedEventDetail.final_status) ||
        isEventStatusFinished(selectedEventDetail.status)
      );
    }
    return false;
  }, [detail, isEventStatusFinished, selectedEventDetail, selectedEventId]);

  useEffect(() => {
    if (!eventDrawerOpen) {
      setOpencodeRows([]);
      return;
    }
    if (!selectedEventDetail || !isCodeAgentEventDetail) {
      setOpencodeRows([]);
      return;
    }
    const eventIdNum = Number(selectedEventId);
    if (!Number.isFinite(eventIdNum)) {
      return;
    }

    setOpencodeRows([]);

    let cancelled = false;
    const fetchPage = async (afterId?: number) => {
      const res = await listEventOpencodeEventsApiEventsEventIdOpencodeGet({
        event_id: eventIdNum,
        ...(afterId !== undefined && afterId > 0 ? { after_id: afterId } : {}),
      });
      const list = Array.isArray(res?.data) ? res.data : [];
      return list;
    };

    const runInitial = async () => {
      setOpencodeLoading(true);
      try {
        const list = await fetchPage();
        if (cancelled) return;
        setOpencodeRows(list);
      } catch {
        if (!cancelled) {
          message.error('加载 OpenCode 执行事件失败');
          setOpencodeRows([]);
        }
      } finally {
        if (!cancelled) {
          setOpencodeLoading(false);
        }
      }
    };

    void runInitial();

    // 事件已终结：只做一次首次加载，不再轮询
    if (selectedEventFinished) {
      return () => {
        cancelled = true;
      };
    }

    const pollId = window.setInterval(() => {
      void (async () => {
        const prev = opencodeRowsRef.current;
        const maxId = prev.reduce((m, r) => Math.max(m, r.id), 0);
        try {
          const list = maxId > 0 ? await fetchPage(maxId) : await fetchPage();
          if (cancelled || !list.length) return;
          setOpencodeRows((cur) => mergeOpencodeRowsById(cur, list));
        } catch {
          // 轮询失败静默，避免每 5s 打搅用户
        }
      })();
    }, 5000);

    return () => {
      cancelled = true;
      window.clearInterval(pollId);
    };
  }, [
    eventDrawerOpen,
    isCodeAgentEventDetail,
    selectedEventDetail,
    selectedEventFinished,
    selectedEventId,
  ]);

  /** OpenCode 执行流：按视口底部到该区域顶部的剩余空间自适应 max-height */
  useLayoutEffect(() => {
    if (!eventDrawerOpen || !isCodeAgentEventDetail) {
      setOpencodeStreamMaxHeightPx(null);
      return;
    }

    const el = opencodeStreamScrollRef.current;
    if (!el) return;

    const measure = () => {
      const vv = window.visualViewport;
      const viewportBottom = vv ? vv.offsetTop + vv.height : window.innerHeight;
      const rect = el.getBoundingClientRect();
      const raw =
        viewportBottom - rect.top - OPENCODE_STREAM_VIEWPORT_BOTTOM_GAP;
      const next = Math.floor(
        Math.min(Math.max(raw, OPENCODE_STREAM_MIN_HEIGHT), 16000),
      );
      setOpencodeStreamMaxHeightPx((prev) => (prev === next ? prev : next));
    };

    measure();
    const raf = requestAnimationFrame(measure);

    const drawerBody = el.closest('.ant-drawer-body');
    const ro = new ResizeObserver(() => {
      requestAnimationFrame(measure);
    });
    if (drawerBody) {
      ro.observe(drawerBody);
    }
    ro.observe(el);

    const visualViewport = window.visualViewport;
    window.addEventListener('resize', measure);
    visualViewport?.addEventListener('resize', measure);
    visualViewport?.addEventListener('scroll', measure);

    const t1 = window.setTimeout(measure, 120);
    const t2 = window.setTimeout(measure, 400);

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      window.removeEventListener('resize', measure);
      visualViewport?.removeEventListener('resize', measure);
      visualViewport?.removeEventListener('scroll', measure);
      window.clearTimeout(t1);
      window.clearTimeout(t2);
    };
  }, [
    eventDrawerOpen,
    isCodeAgentEventDetail,
    eventDetailLoading,
    opencodeLoading,
    selectedEventDetail,
    opencodeStreamItems.length,
  ]);

  const handleOpenEventDetail = useCallback(async (eventId: string) => {
    const numericEventId = Number(eventId);
    if (!Number.isFinite(numericEventId)) {
      message.error('事件 ID 无效，无法加载详情');
      return;
    }
    setSelectedEventId(eventId);
    setEventDrawerOpen(true);
    setOpencodeRows([]);
    setEventDetailLoading(true);
    try {
      const res = await getEventApiEventsEventIdGet({
        event_id: numericEventId,
      });
      if (res?.success && res.data) {
        setSelectedEventDetail(res.data);
      } else {
        setSelectedEventDetail(null);
        message.error('加载事件详情失败');
      }
    } catch {
      setSelectedEventDetail(null);
      message.error('加载事件详情失败');
    } finally {
      setEventDetailLoading(false);
    }
  }, []);

  const handleOpenHumanApprovalPlan = useCallback(
    async (interactionId: string, eventId?: string) => {
      if (!interactionId) return;
      setPlanModalLoading(true);
      setPlanInteractionId(interactionId);
      setPlanEventId(eventId ?? '');
      setPlanModalOpen(true);
      try {
        const cachedData = humanApprovalMetaMap[interactionId];
        const data = cachedData
          ? cachedData
          : (((
              await getHumanApprovalApiEventsHumanApprovalsInteractionIdGet({
                interaction_id: interactionId,
              })
            )?.data ?? {}) as HumanApprovalPayload);
        setHumanApprovalMetaMap((prev) => ({ ...prev, [interactionId]: data }));
        setPlanCreatedAt(data.created_at || '');
        setPlanTimeoutSeconds(Number(data.timeout_seconds ?? 0) || 0);
        if ((data.interaction_type || '').toLowerCase() !== 'plan') {
          setPlanRows([]);
          message.warning('当前审批类型不是 plan，暂不展示计划表格');
        } else {
          setPlanRows(parsePlanRowsFromMessage(data.message));
        }
      } catch {
        setPlanRows([]);
        message.error('加载 human approval 详情失败');
      } finally {
        setPlanModalLoading(false);
      }
    },
    [humanApprovalMetaMap],
  );

  const handleSavePlanDraft = useCallback((): boolean => {
    const serialized = serializePlanRowsToMessage(planRows);
    try {
      JSON.parse(serialized);
      message.success('已保存当前修改（本地草稿）');
      return true;
    } catch {
      message.error('保存失败，数据格式无效');
      return false;
    }
  }, [planRows]);

  const handleSubmitHumanApproval = useCallback(
    async (approved: boolean) => {
      if (!planInteractionId) return;
      if (approved && !handleSavePlanDraft()) {
        return;
      }
      try {
        await resolveHumanApprovalApiEventsHumanApprovalsInteractionIdPost(
          {
            interaction_id: planInteractionId,
            ...(planEventId ? { event_id: planEventId } : {}),
          } as API.resolveHumanApprovalApiEventsHumanApprovalsInteractionIdPostParams & {
            event_id?: string;
          },
          {
            approved,
            operator: 'user',
            message: serializePlanRowsToMessage(planRows),
          },
        );
        message.success(approved ? '已接受并提交' : '已拒绝并提交');
        setHumanApprovalMetaMap((prev) => ({
          ...prev,
          [planInteractionId]: {
            ...(prev[planInteractionId] ?? {}),
            approved,
            decided_by: 'user',
          },
        }));
        setHandledInteractionIds((prev) =>
          prev.includes(planInteractionId)
            ? prev
            : [...prev, planInteractionId],
        );
        setPlanModalOpen(false);
        void load();
      } catch {
        message.error('提交审批结果失败');
      }
    },
    [handleSavePlanDraft, load, planEventId, planInteractionId, planRows],
  );

  useEffect(() => {
    if (!detail) return;
    const pendingApprovalEvent = detail.events.find((e) => {
      const isHumanApproval =
        (e.actionType || '').toLowerCase() === 'human_approval';
      const status = (e.finalStatus || e.status || '').toLowerCase();
      return (
        isHumanApproval && (status === 'running' || status === 'in_progress')
      );
    });
    const interactionId = pendingApprovalEvent?.reason?.trim() ?? '';
    if (!interactionId) return;
    if (handledInteractionIds.includes(interactionId)) return;
    if (interactionId === planInteractionId && planModalOpen) return;
    void handleOpenHumanApprovalPlan(interactionId, pendingApprovalEvent?.id);
  }, [
    detail,
    handledInteractionIds,
    handleOpenHumanApprovalPlan,
    planInteractionId,
    planModalOpen,
  ]);

  useEffect(() => {
    if (missingHumanApprovalInteractionIds.length === 0) return;
    void (async () => {
      const entries = await Promise.all(
        missingHumanApprovalInteractionIds.map(async (interactionId) => {
          try {
            const res =
              await getHumanApprovalApiEventsHumanApprovalsInteractionIdGet({
                interaction_id: interactionId,
              });
            return [
              interactionId,
              (res?.data ?? {}) as HumanApprovalPayload,
            ] as const;
          } catch {
            return null;
          }
        }),
      );
      const next = entries.filter(
        (item): item is readonly [string, HumanApprovalPayload] =>
          item !== null,
      );
      if (next.length === 0) return;
      setHumanApprovalMetaMap((prev) => ({
        ...prev,
        ...Object.fromEntries(next),
      }));
    })();
  }, [missingHumanApprovalInteractionIds]);

  const planCountdownText = useMemo(() => {
    if (!planCreatedAt || !planTimeoutSeconds) return '--';
    const createdMs = utcApiStringToEpochMs(planCreatedAt);
    if (createdMs == null) return '--';
    const expireAt = createdMs + planTimeoutSeconds * 1000;
    const remaining = Math.max(0, Math.floor((expireAt - countdownNow) / 1000));
    const min = Math.floor(remaining / 60);
    const sec = remaining % 60;
    return `${String(min).padStart(2, '0')}:${String(sec).padStart(2, '0')}`;
  }, [countdownNow, planCreatedAt, planTimeoutSeconds]);

  const updatePlanRow = useCallback(
    (rowId: string, key: keyof PlanRow, value: string | number) => {
      setPlanRows((prev) =>
        prev.map((row) => (row.id === rowId ? { ...row, [key]: value } : row)),
      );
    },
    [],
  );

  const addPlanLanguage = useCallback((): string => {
    const language_group_id = makeLanguageGroupId();
    setPlanRows((prev) => [
      ...prev,
      {
        id: `row-${Date.now()}`,
        language_group_id,
        language: '',
        language_level: 1,
        category_name: '',
        level: 1,
        risk_description: '',
        reasoning_basis: '',
      },
    ]);
    return language_group_id;
  }, []);

  const addPlanCategory = useCallback((languageGroupId: string) => {
    setPlanRows((prev) => {
      const sample = prev.find((r) => r.language_group_id === languageGroupId);
      if (!sample) return prev;
      return [
        ...prev,
        {
          id: `row-${Date.now()}`,
          language_group_id: languageGroupId,
          language: sample.language,
          language_level: sample.language_level,
          category_name: '',
          level: 1,
          risk_description: '',
          reasoning_basis: '',
        },
      ];
    });
  }, []);

  const setLanguageGroupLanguage = useCallback(
    (languageGroupId: string, language: string) => {
      setPlanRows((prev) =>
        prev.map((row) =>
          row.language_group_id === languageGroupId
            ? { ...row, language }
            : row,
        ),
      );
    },
    [],
  );

  const setLanguageGroupLevel = useCallback(
    (languageGroupId: string, language_level: number) => {
      const n = Number(language_level) || 1;
      setPlanRows((prev) =>
        prev.map((row) =>
          row.language_group_id === languageGroupId
            ? { ...row, language_level: n }
            : row,
        ),
      );
    },
    [],
  );

  const removeLanguageGroup = useCallback((languageGroupId: string) => {
    setPlanRows((prev) =>
      prev.filter((row) => row.language_group_id !== languageGroupId),
    );
  }, []);

  const removePlanRow = useCallback((rowId: string) => {
    setPlanRows((prev) => prev.filter((row) => row.id !== rowId));
  }, []);

  const {
    data: completionStatus,
    loading: completionLoading,
    error: completionError,
    progress: completionProgress,
    reload: reloadCompletionStatus,
  } = useTaskCompletionStatus(taskId);

  useEffect(() => {
    reloadCompletionRef.current = reloadCompletionStatus;
  }, [reloadCompletionStatus]);

  // 任务运行时轮询报告数据（快速扫描统计、覆盖率）；完成后做一次最终获取
  useEffect(() => {
    if (!taskId || !detail) return;
    const taskStatus = detail.session.status;
    const isFinished = taskStatus === 'completed' || taskStatus === 'failed';

    let cancelled = false;
    let timerId: number | undefined;

    const fetchReport = async () => {
      try {
        const res = await getReportApiReportsTaskIdGet({ task_id: taskId });
        if (cancelled || !res?.success || !res.data) return;
        const d = res.data as Record<string, any>;
        const qs = d.quick_scan ?? {};
        const cov = d.coverage ?? {};
        const hr = d.html_report ?? {};
        const sev = d.summary?.severity ?? {};
        setQuickScanData({
          completed: Boolean(qs.completed),
          findingsCount: Number(qs.findings_count ?? 0),
          reason: String(qs.reason ?? ''),
          coverage: {
            coverage_rate: Number(cov.coverage_rate ?? 0),
            reviewed_files: Number(cov.reviewed_files ?? 0),
            total_files: Number(cov.total_files ?? 0),
          },
          htmlReportAvailable: Boolean(hr.available),
          severityCounts: {
            critical: Number(sev.C ?? 0),
            high: Number(sev.H ?? 0),
            medium: Number(sev.M ?? 0),
            low: Number(sev.L ?? 0),
          },
        });
      } catch {
        // 报告数据获取失败不影响主流程
      }
    };

    if (isFinished) {
      // 已完成/失败：仅获取一次
      void fetchReport();
    } else {
      // 运行中：轮询（每10秒），完成后自动停止
      timerId = window.setInterval(() => {
        if (cancelled) return;
        void fetchReport();
      }, 10_000);
      // 首次立即获取
      void fetchReport();
    }

    return () => {
      cancelled = true;
      if (timerId !== undefined) window.clearInterval(timerId);
    };
  }, [taskId, detail?.session.status]);

  const handleViewHtmlReport = useCallback(async () => {
    if (!taskId) return;
    try {
      const blob = await downloadHtmlReportApiReportsTaskIdHtmlGet({ task_id: taskId });
      const url = window.URL.createObjectURL(blob);
      window.open(url, '_blank', 'noopener,noreferrer');
      // 延迟释放，确保新窗口已加载
      setTimeout(() => window.URL.revokeObjectURL(url), 3000);
    } catch {
      message.error('获取报告失败');
    }
  }, [taskId]);

  const handleLoadOlderEvents = useCallback(async () => {
    if (!taskId || loadingOlderEvents) {
      return;
    }
    const beforeId = eventListMeta?.pageOldestId;
    if (beforeId == null || !eventListMeta?.hasMoreOlder) {
      return;
    }
    setLoadingOlderEvents(true);
    try {
      const { events, meta } = await listTaskEventsOlder(taskId, beforeId);
      if (events.length === 0) {
        setEventListMeta((prev) =>
          prev ? { ...prev, hasMoreOlder: false } : prev,
        );
        return;
      }
      const prev = detailRef.current;
      if (!prev) {
        return;
      }
      const merged = mergeOlderTaskEventsIntoDetail(prev, events);
      setDetail(merged);
      setEventListMeta((prevMeta) => ({
        total: meta.total,
        hasMoreOlder: meta.hasMoreOlder,
        pageOldestId: meta.pageOldestId,
        pageNewestId: prevMeta?.pageNewestId ?? meta.pageNewestId,
      }));
    } catch {
      message.error('加载更早事件失败');
    } finally {
      setLoadingOlderEvents(false);
    }
  }, [taskId, eventListMeta, loadingOlderEvents]);

  const moduleTabs = useMemo(
    () =>
      detail
        ? buildTaskDetailModuleTabs({
            detail,
            sortedEvents,
            eventsTotal: eventListMeta?.total,
            hasMoreOlder: eventListMeta?.hasMoreOlder,
            loadingOlderEvents,
            onLoadOlderEvents: handleLoadOlderEvents,
            humanApprovalMetaMap,
            onOpenEventDetail: handleOpenEventDetail,
            onRequestFocusAuditChainNode: handleRequestFocusAuditChainNode,
            completionStatus,
            completionLoading,
            completionError,
            completionCompleted: completionProgress.completed,
            completionTotal: completionProgress.total,
            onReloadCompletionStatus: () => {
              void reloadCompletionStatus();
            },
            quickScanData,
          })
        : [],
    [
      detail,
      eventListMeta,
      handleLoadOlderEvents,
      humanApprovalMetaMap,
      loadingOlderEvents,
      sortedEvents,
      handleOpenEventDetail,
      handleRequestFocusAuditChainNode,
      completionStatus,
      completionLoading,
      completionError,
      completionProgress.completed,
      completionProgress.total,
      reloadCompletionStatus,
      quickScanData,
    ],
  );

  if (!taskId) {
    return (
      <PageContainer title="任务详情">
        <Empty description="缺少任务 ID" />
      </PageContainer>
    );
  }

  return (
    <PageContainer
      onBack={() => history.push('/tasks')}
      title="任务详情"
      subTitle={detail?.session.taskName}
      extra={[
        detail?.session.status === 'failed' ? (
          <Button
            key="retry"
            color="danger"
            variant="solid"
            onClick={async () => {
              if (!taskId) return;
              try {
                await retryTaskApiTasksTaskIdRetryGet({ task_id: taskId });
                message.success('任务已重新执行');
                void load();
              } catch {
                message.error('重试失败');
              }
            }}
          >
            重试
          </Button>
        ) : null,
        quickScanData?.htmlReportAvailable ? (
          <Button
            key="view-report"
            type="primary"
            icon={<LinkOutlined />}
            onClick={() => handleViewHtmlReport()}
          >
            查看报告
          </Button>
        ) : null,
        detail?.session.status === 'completed' ? (
          <Button
            key="regenerate-report"
            icon={<LinkOutlined />}
            onClick={async () => {
              if (!taskId) return;
              try {
                await regenerateHtmlReportApiReportsTaskIdRegeneratePost({ task_id: taskId });
                message.success('报告已重新生成');
                // 刷新报告数据
                const res = await getReportApiReportsTaskIdGet({ task_id: taskId });
                if (res?.success && res.data) {
                  const d = res.data as Record<string, any>;
                  const qs = d.quick_scan ?? {};
                  const cov = d.coverage ?? {};
                  const hr = d.html_report ?? {};
                  const sev = d.summary?.severity ?? {};
                  setQuickScanData({
                    completed: Boolean(qs.completed),
                    findingsCount: Number(qs.findings_count ?? 0),
                    reason: String(qs.reason ?? ''),
                    coverage: {
                      coverage_rate: Number(cov.coverage_rate ?? 0),
                      reviewed_files: Number(cov.reviewed_files ?? 0),
                      total_files: Number(cov.total_files ?? 0),
                    },
                    htmlReportAvailable: Boolean(hr.available),
                    severityCounts: {
                      critical: Number(sev.C ?? 0),
                      high: Number(sev.H ?? 0),
                      medium: Number(sev.M ?? 0),
                      low: Number(sev.L ?? 0),
                    },
                  });
                }
                void load();
              } catch {
                message.error('重新生成失败');
              }
            }}
          >
            重新生成报告
          </Button>
        ) : null,
        <Button key="tasks" onClick={() => history.push('/tasks')}>
          返回任务列表
        </Button>,
      ]}
    >
      <Spin spinning={loading}>
        {!detail && !loading ? (
          <Empty description="未找到该任务或运行详情" />
        ) : detail ? (
          <div
            style={{
              display: 'flex',
              flexWrap: auditChainPageExpand ? 'nowrap' : 'wrap',
              gap: auditChainPageExpand ? 0 : 16,
              alignItems: 'stretch',
              minHeight: TASK_DETAIL_MAIN_COLUMNS_HEIGHT,
            }}
          >
            <div
              style={
                auditChainPageExpand
                  ? { display: 'none' }
                  : {
                      flex: '1 1 520px',
                      minWidth: 0,
                      height: TASK_DETAIL_MAIN_COLUMNS_HEIGHT,
                      maxHeight: TASK_DETAIL_MAIN_COLUMNS_HEIGHT,
                      display: 'flex',
                      flexDirection: 'column',
                      minHeight: 0,
                      overflow: 'hidden',
                      paddingRight: 4,
                    }
              }
            >
              <Tabs
                rootClassName={TASK_DETAIL_MODULE_TABS_CLASS}
                defaultActiveKey="events"
                type="line"
                size="middle"
                items={moduleTabs}
                tabBarGutter={20}
                destroyInactiveTabPane={false}
                style={{ height: '100%', minHeight: 0 }}
              />
            </div>

            <div
              ref={auditChainTrayRef}
              className={TASK_DETAIL_AUDIT_CHAIN_TRAY_CLASS}
              style={{
                flex: auditChainPageExpand ? '1 1 100%' : '1 1 400px',
                maxWidth: '100%',
                overflow: 'hidden',
                minWidth: 0,
                display: 'flex',
                flexDirection: 'column',
                boxSizing: 'border-box',
                height: TASK_DETAIL_MAIN_COLUMNS_HEIGHT,
                maxHeight: TASK_DETAIL_MAIN_COLUMNS_HEIGHT,
                padding: TASK_DETAIL_AUDIT_CHAIN_TRAY_PADDING,
                background: 'var(--ant-color-fill-quaternary)',
                borderRadius: 'var(--ant-border-radius-lg)',
                boxShadow: 'inset 0 0 0 1px var(--ant-color-split)',
                ...(auditChainPageExpand ? { width: '100%' } : {}),
              }}
            >
              <Card
                size="small"
                variant="borderless"
                styles={{
                  body: {
                    padding: 0,
                    flex: 1,
                    minHeight: 0,
                    minWidth: 320,
                    display: 'flex',
                    flexDirection: 'column',
                  },
                }}
                style={{
                  flex: 1,
                  minHeight: 0,
                  maxWidth: '100%',
                  overflow: 'hidden',
                  display: 'flex',
                  flexDirection: 'column',
                  background: 'var(--ant-color-bg-container)',
                  border: '1px solid var(--ant-color-split)',
                  borderRadius: 'var(--ant-border-radius-lg)',
                  boxShadow:
                    '0 0 0 1px rgba(15, 23, 42, 0.06), 0 4px 14px rgba(15, 23, 42, 0.1)',
                }}
              >
                <div
                  style={{
                    flex: 1,
                    minHeight: 0,
                    borderRadius: 8,
                    overflow: 'hidden',
                    display: 'flex',
                    flexDirection: 'column',
                  }}
                >
                  <AuditChainCanvas
                    graphKey={graphKey}
                    raw={auditChainGraph}
                    taskName={detail.session.taskName}
                    focusNodeRequest={auditChainFocusRequest}
                    headerExtraRight={
                      <Space size={4}>
                        <Button
                          type="text"
                          size="small"
                          title={
                            auditChainPageExpand ? '退出页内放大' : '页内放大'
                          }
                          aria-label={
                            auditChainPageExpand ? '退出页内放大' : '页内放大'
                          }
                          icon={
                            auditChainPageExpand ? (
                              <CompressOutlined />
                            ) : (
                              <ExpandOutlined />
                            )
                          }
                          onClick={toggleAuditChainPageExpand}
                        />
                        <Button
                          type="text"
                          size="small"
                          title={
                            auditChainBrowserFullscreen ? '退出全屏' : '全屏'
                          }
                          aria-label={
                            auditChainBrowserFullscreen ? '退出全屏' : '全屏'
                          }
                          icon={
                            auditChainBrowserFullscreen ? (
                              <FullscreenExitOutlined />
                            ) : (
                              <FullscreenOutlined />
                            )
                          }
                          onClick={() =>
                            void toggleAuditChainBrowserFullscreen()
                          }
                        />
                      </Space>
                    }
                  />
                </div>
              </Card>
            </div>
          </div>
        ) : null}
      </Spin>
      <TaskEventDetailDrawer
        open={eventDrawerOpen}
        selectedEventId={selectedEventId}
        onClose={() => {
          setEventDrawerOpen(false);
          setSelectedEventDetail(null);
          setSelectedEventId('');
          setOpencodeRows([]);
        }}
        detailLoading={eventDetailLoading}
        eventDetail={selectedEventDetail}
        isCodeAgentEventDetail={isCodeAgentEventDetail}
        opencodeLoading={opencodeLoading}
        opencodeStreamScrollRef={opencodeStreamScrollRef}
        opencodeStreamMaxHeightPx={opencodeStreamMaxHeightPx}
        opencodeStreamItems={opencodeStreamItems}
      />
      <PlanApprovalModal
        open={planModalOpen}
        onCancel={() => setPlanModalOpen(false)}
        title={`需要确认审计计划（倒计时 ${planCountdownText}）`}
        loading={planModalLoading}
        planRows={planRows}
        addPlanLanguage={addPlanLanguage}
        addPlanCategory={addPlanCategory}
        setLanguageGroupLanguage={setLanguageGroupLanguage}
        setLanguageGroupLevel={setLanguageGroupLevel}
        removeLanguageGroup={removeLanguageGroup}
        onSaveDraft={handleSavePlanDraft}
        onReject={() => void handleSubmitHumanApproval(false)}
        onApprove={() => void handleSubmitHumanApproval(true)}
        updatePlanRow={updatePlanRow}
        removePlanRow={removePlanRow}
      />
    </PageContainer>
  );
};

ensureTaskDetailPageStylesMounted();

export default TaskDetailPage;
