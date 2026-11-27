import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ApiError,
  buildQueryString,
  fetchEvents,
  fetchHosts,
  fetchSummary,
  timeRangeToFromIso,
} from "./api";

describe("api client", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("computes ISO timestamps for time ranges", () => {
    const now = new Date("2026-11-26T12:00:00.000Z");
    expect(timeRangeToFromIso("1h", now)).toBe("2026-11-26T11:00:00.000Z");
    expect(timeRangeToFromIso("24h", now)).toBe("2026-11-25T12:00:00.000Z");
    expect(timeRangeToFromIso("7d", now)).toBe("2026-11-19T12:00:00.000Z");
    expect(timeRangeToFromIso("30d", now)).toBe("2026-10-27T12:00:00.000Z");
  });

  it("builds query string skipping undefined and empty values", () => {
    expect(
      buildQueryString({
        page: 2,
        page_size: 50,
        host: "",
        action: "ban",
        q: undefined,
        observed: false,
      }),
    ).toBe("?page=2&page_size=50&action=ban&observed=false");
    expect(buildQueryString({ host: "" })).toBe("");
  });

  it("fetches events, hosts, and summary with expected URLs", async () => {
    const fetchMock = vi.fn<typeof fetch>(async (input) => {
      const url = String(input);
      if (url.startsWith("./api/hosts")) {
        return { ok: true, json: async () => ({ hosts: [] }) } as Response;
      }
      if (url.startsWith("./api/summary")) {
        return {
          ok: true,
          json: async () => ({
            total: 0,
            counted: 0,
            ban: 0,
            observed: 0,
            top_hosts: [],
            top_reasons: [],
          }),
        } as Response;
      }
      return {
        ok: true,
        json: async () => ({ items: [], total: 0, page: 1, page_size: 50 }),
      } as Response;
    });
    vi.stubGlobal("fetch", fetchMock);

    await fetchEvents({ host: "app.example.com", page: 1, page_size: 25, q: "1.2.3.4" });
    expect(fetchMock).toHaveBeenCalledWith(
      "./api/events?page=1&page_size=25&host=app.example.com&q=1.2.3.4",
      expect.objectContaining({ headers: { Accept: "application/json" } }),
    );

    await fetchHosts({ from: "2026-11-25T00:00:00Z" });
    expect(fetchMock).toHaveBeenCalledWith(
      "./api/hosts?from=2026-11-25T00%3A00%3A00Z",
      expect.any(Object),
    );

    await fetchSummary({ from: "2026-11-25T00:00:00Z" });
    expect(fetchMock).toHaveBeenCalledWith(
      "./api/summary?from=2026-11-25T00%3A00%3A00Z",
      expect.any(Object),
    );
  });

  it("throws ApiError on non-JSON 200 response or invalid shape", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => {
          throw new SyntaxError("Unexpected token '<'");
        },
      } as unknown as Response),
    );

    await expect(fetchEvents({})).rejects.toEqual(
      new ApiError(200, "Unexpected non-JSON response from server"),
    );

    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ unexpected: true }),
      } as Response),
    );

    await expect(fetchEvents({})).rejects.toEqual(
      new ApiError(500, "Invalid response shape from ./api/events"),
    );
  });

  it("throws ApiError with server error message when response is not ok", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue({
      ok: false,
      status: 400,
      json: async () => ({ error: "invalid 'from' timestamp, expected RFC3339" }),
    } as Response);
    vi.stubGlobal("fetch", fetchMock);

    await expect(fetchEvents({ from: "bad" })).rejects.toEqual(
      new ApiError(400, "invalid 'from' timestamp, expected RFC3339"),
    );
  });
});
