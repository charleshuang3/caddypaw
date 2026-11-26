import type { SecurityEvent } from "../types/security";

export function formatLocalDateTime(iso?: string | null): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function formatRelativeTime(iso?: string | null, nowMs: number = Date.now()): string {
  if (!iso) return "—";
  const targetMs = new Date(iso).getTime();
  if (Number.isNaN(targetMs)) return "—";

  const diffSec = Math.round((nowMs - targetMs) / 1000);
  const absSec = Math.abs(diffSec);
  const isFuture = diffSec < 0;

  let unit: string;
  if (absSec < 5) {
    return isFuture ? "in a moment" : "just now";
  } else if (absSec < 60) {
    unit = `${absSec}s`;
  } else if (absSec < 3600) {
    unit = `${Math.floor(absSec / 60)}m`;
  } else if (absSec < 86400) {
    unit = `${Math.floor(absSec / 3600)}h`;
  } else {
    unit = `${Math.floor(absSec / 86400)}d`;
  }

  return isFuture ? `in ${unit}` : `${unit} ago`;
}

export function splitReasons(reason: string): string[] {
  if (!reason) return [];
  return reason
    .split(" | ")
    .map((part) => part.trim())
    .filter((part) => part.length > 0);
}

export function isWafReason(reason: string): boolean {
  return reason.trim().toLowerCase().startsWith("waf:");
}

export function formatGeoLocation(ev: Pick<SecurityEvent, "city" | "country">): string {
  const parts = [ev.city.trim(), ev.country.trim()].filter((p) => p.length > 0);
  return parts.length > 0 ? parts.join(", ") : "—";
}

export function actionBadgeClass(action: string): string {
  switch (action) {
    case "ban":
      return "badge-error";
    case "count error":
      return "badge-warning";
    case "observed":
      return "badge-info";
    case "banned":
      return "badge-neutral";
    default:
      return "badge-ghost";
  }
}

export function methodBadgeClass(method: string): string {
  switch (method.toUpperCase()) {
    case "GET":
    case "HEAD":
      return "badge-info badge-outline";
    case "POST":
    case "PUT":
    case "PATCH":
      return "badge-warning badge-outline";
    case "DELETE":
      return "badge-error badge-outline";
    default:
      return "badge-ghost badge-outline";
  }
}
