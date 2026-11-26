export type TimeRangeKey = "1h" | "24h" | "7d" | "30d";

export type EventActionFilter = "" | "count error" | "ban" | "banned" | "observed";

export interface SecurityEvent {
  id: number;
  created_at: string;
  host: string;
  ip: string;
  method: string;
  path: string;
  reason: string;
  weight: number;
  observed: boolean;
  action: string;
  jail_until?: string | null;
  country: string;
  city: string;
  asn: string;
}

export interface HostEventCount {
  host: string;
  count: number;
}

export interface ReasonEventCount {
  reason: string;
  count: number;
}

export interface SecurityEventSummary {
  total: number;
  counted: number;
  ban: number;
  observed: number;
  top_hosts: HostEventCount[];
  top_reasons: ReasonEventCount[];
}

export interface EventsResponse {
  items: SecurityEvent[];
  total: number;
  page: number;
  page_size: number;
}

export interface HostsResponse {
  hosts: HostEventCount[];
}

export interface EventsQueryParams {
  from?: string;
  to?: string;
  page?: number;
  page_size?: number;
  host?: string;
  ip?: string;
  action?: string;
  observed?: boolean;
  q?: string;
}
