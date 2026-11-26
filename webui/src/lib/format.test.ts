import { describe, expect, it } from "vitest";
import {
  actionBadgeClass,
  formatGeoLocation,
  formatLocalDateTime,
  formatRelativeTime,
  isWafReason,
  methodBadgeClass,
  splitReasons,
} from "./format";

describe("format helpers", () => {
  it("formats relative time for past and future timestamps", () => {
    const now = Date.UTC(2026, 10, 26, 12, 0, 0);
    expect(formatRelativeTime(new Date(now - 2000).toISOString(), now)).toBe("just now");
    expect(formatRelativeTime(new Date(now - 30_000).toISOString(), now)).toBe("30s ago");
    expect(formatRelativeTime(new Date(now - 5 * 60_000).toISOString(), now)).toBe("5m ago");
    expect(formatRelativeTime(new Date(now - 3 * 3600_000).toISOString(), now)).toBe("3h ago");
    expect(formatRelativeTime(new Date(now - 2 * 86400_000).toISOString(), now)).toBe("2d ago");
    expect(formatRelativeTime(new Date(now + 15 * 60_000).toISOString(), now)).toBe("in 15m");
    expect(formatRelativeTime(null, now)).toBe("—");
    expect(formatRelativeTime("invalid-date", now)).toBe("—");
  });

  it("formats local date time safely", () => {
    expect(formatLocalDateTime(undefined)).toBe("—");
    expect(formatLocalDateTime("")).toBe("—");
    expect(formatLocalDateTime("not-a-date")).toBe("—");
    expect(formatLocalDateTime("2026-11-26T12:00:00Z")).not.toBe("—");
  });

  it("splits pipe-delimited reasons and identifies WAF reasons", () => {
    expect(splitReasons("")).toEqual([]);
    expect(splitReasons("waf:942100 | basic_auth failed")).toEqual([
      "waf:942100",
      "basic_auth failed",
    ]);
    expect(isWafReason("waf:942100")).toBe(true);
    expect(isWafReason("WAF:920350")).toBe(true);
    expect(isWafReason("basic_auth failed")).toBe(false);
  });

  it("formats geo location", () => {
    expect(formatGeoLocation({ city: "Tokyo", country: "JP" })).toBe("Tokyo, JP");
    expect(formatGeoLocation({ city: "", country: "US" })).toBe("US");
    expect(formatGeoLocation({ city: "", country: "" })).toBe("—");
  });

  it("maps action and method badge classes", () => {
    expect(actionBadgeClass("ban")).toBe("badge-error");
    expect(actionBadgeClass("count error")).toBe("badge-warning");
    expect(actionBadgeClass("observed")).toBe("badge-info");
    expect(actionBadgeClass("banned")).toBe("badge-neutral");
    expect(actionBadgeClass("other")).toBe("badge-ghost");

    expect(methodBadgeClass("GET")).toContain("badge-info");
    expect(methodBadgeClass("POST")).toContain("badge-warning");
    expect(methodBadgeClass("DELETE")).toContain("badge-error");
    expect(methodBadgeClass("OPTIONS")).toContain("badge-ghost");
  });
});
