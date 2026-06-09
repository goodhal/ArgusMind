// @ts-ignore
/* eslint-disable */
import { request } from "@umijs/max";

/** Get Report GET /api/reports/${param0} */
export async function getReportApiReportsTaskIdGet(
  // 叠加生成的Param类型 (非body参数swagger默认没有生成对象)
  params: API.getReportApiReportsTaskIdGetParams,
  options?: { [key: string]: any }
) {
  const { task_id: param0, ...queryParams } = params;
  return request<API.OkResponseDict_>(`/api/reports/${param0}`, {
    method: "GET",
    params: { ...queryParams },
    ...(options || {}),
  });
}

/** Download HTML Report GET /api/reports/${param0}/html */
export async function downloadHtmlReportApiReportsTaskIdHtmlGet(
  params: API.getReportApiReportsTaskIdGetParams,
  options?: { [key: string]: any }
) {
  const { task_id: param0 } = params;
  return request<Blob>(`/api/reports/${param0}/html`, {
    method: "GET",
    responseType: "blob",
    ...(options || {}),
  });
}

/** Regenerate HTML Report POST /api/reports/${param0}/regenerate */
export async function regenerateHtmlReportApiReportsTaskIdRegeneratePost(
  params: API.getReportApiReportsTaskIdGetParams,
  options?: { [key: string]: any }
) {
  const { task_id: param0 } = params;
  return request<API.OkResponseDict_>(`/api/reports/${param0}/regenerate`, {
    method: "POST",
    ...(options || {}),
  });
}
