import type {
  EventsQueryParams,
  EventsResponse,
  HostsResponse,
  SecurityEventSummary,
  TimeRangeKey,
} from "../types/security";

export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

const RANGE_MS: Record<TimeRangeKey, number> = {
  "1h": 60 * 60 * 1000,
  "24h": 24 * 60 * 60 * 1000,
  "7d": 7 * 24 * 60 * 60 * 1000,
  "30d": 30 * 24 * 60 * 60 * 1000,
};

export function timeRangeToFromIso(range: TimeRangeKey, now: Date = new Date()): string {
  const from = new Date(now.getTime() - RANGE_MS[range]);
  return from.toISOString();
}

export function buildQueryString(
  params: Record<string, string | number | boolean | undefined>,
): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === "") {
      continue;
    }
    search.set(key, String(value));
  }
  const encoded = search.toString();
  return encoded ? `?${encoded}` : "";
}

const REQUEST_TIMEOUT_MS = 15_000;

async function fetchJson<T>(url: string, signal?: AbortSignal): Promise<T> {
  const timeoutSignal =
    typeof AbortSignal.timeout === "function" ? AbortSignal.timeout(REQUEST_TIMEOUT_MS) : undefined;
  const combinedSignal =
    signal && timeoutSignal && typeof AbortSignal.any === "function"
      ? AbortSignal.any([signal, timeoutSignal])
      : (signal ?? timeoutSignal);

  const response = await fetch(url, {
    headers: { Accept: "application/json" },
    signal: combinedSignal,
  });

  if (!response.ok) {
    let message = `HTTP ${response.status}`;
    try {
      const body = (await response.json()) as { error?: unknown };
      if (typeof body.error === "string" && body.error.trim() !== "") {
        message = body.error;
      }
    } catch {
      // Ignore non-JSON error bodies and keep status fallback.
    }
    throw new ApiError(response.status, message);
  }

  let data: unknown;
  try {
    data = await response.json();
  } catch {
    throw new ApiError(response.status, "Unexpected non-JSON response from server");
  }
  return data as T;
}

export async function fetchEvents(
  params: EventsQueryParams,
  signal?: AbortSignal,
): Promise<EventsResponse> {
  const qs = buildQueryString({
    from: params.from,
    to: params.to,
    page: params.page,
    page_size: params.page_size,
    host: params.host,
    ip: params.ip,
    action: params.action,
    observed: params.observed,
    q: params.q,
  });
  const data = await fetchJson<EventsResponse>(`/api/events${qs}`, signal);
  if (!data || !Array.isArray(data.items) || typeof data.total !== "number") {
    throw new ApiError(500, "Invalid response shape from /api/events");
  }
  return data;
}

export async function fetchHosts(
  params: { from?: string; to?: string },
  signal?: AbortSignal,
): Promise<HostsResponse> {
  const qs = buildQueryString({
    from: params.from,
    to: params.to,
  });
  const data = await fetchJson<HostsResponse>(`/api/hosts${qs}`, signal);
  if (!data || !Array.isArray(data.hosts)) {
    throw new ApiError(500, "Invalid response shape from /api/hosts");
  }
  return data;
}

export async function fetchSummary(
  params: { from?: string; to?: string },
  signal?: AbortSignal,
): Promise<SecurityEventSummary> {
  const qs = buildQueryString({
    from: params.from,
    to: params.to,
  });
  const data = await fetchJson<SecurityEventSummary>(`/api/summary${qs}`, signal);
  if (!data || !Array.isArray(data.top_hosts) || !Array.isArray(data.top_reasons)) {
    throw new ApiError(500, "Invalid response shape from /api/summary");
  }
  return data;
}
