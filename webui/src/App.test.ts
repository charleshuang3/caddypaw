// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createApp, nextTick } from "vue";
import App from "./App.vue";
import type { EventsResponse, HostsResponse, SecurityEventSummary } from "./types/security";

function flushPromises(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

const sampleSummary: SecurityEventSummary = {
  total: 12,
  counted: 7,
  ban: 3,
  observed: 2,
  top_hosts: [
    { host: "app.example.com", count: 8 },
    { host: "api.example.com", count: 4 },
  ],
  top_reasons: [
    { reason: "waf:942100", count: 6 },
    { reason: "basic_auth failed", count: 4 },
  ],
};

const sampleHosts: HostsResponse = {
  hosts: [
    { host: "app.example.com", count: 8 },
    { host: "api.example.com", count: 4 },
  ],
};

const sampleEvents: EventsResponse = {
  items: [
    {
      id: 101,
      created_at: "2026-11-26T11:55:00Z",
      host: "app.example.com",
      ip: "203.0.113.10",
      method: "POST",
      path: "/login?user=admin",
      reason: "waf:942100 | basic_auth failed",
      weight: 5,
      observed: false,
      action: "ban",
      jail_until: "2026-11-26T12:55:00Z",
      country: "US",
      city: "Seattle",
      asn: "AS12345 ExampleNet",
    },
    {
      id: 102,
      created_at: "2026-11-26T11:50:00Z",
      host: "api.example.com",
      ip: "198.51.100.42",
      method: "GET",
      path: "/v1/health",
      reason: "observed probe",
      weight: 1,
      observed: true,
      action: "observed",
      country: "DE",
      city: "Frankfurt",
      asn: "AS64500 Cloud",
    },
  ],
  total: 2,
  page: 1,
  page_size: 50,
};

describe("App dashboard", () => {
  let container: HTMLDivElement;
  let activeApp: ReturnType<typeof createApp> | null = null;

  beforeEach(() => {
    container = document.createElement("div");
    document.body.appendChild(container);
    localStorage.clear();
  });

  afterEach(() => {
    if (activeApp) {
      activeApp.unmount();
      activeApp = null;
    }
    container.remove();
    vi.unstubAllGlobals();
  });

  function mountApp() {
    activeApp = createApp(App);
    activeApp.mount(container);
    return activeApp;
  }

  function mockFetchSuccess() {
    const fetchMock = vi.fn<typeof fetch>(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.startsWith("./api/summary")) {
        return { ok: true, json: async () => sampleSummary } as Response;
      }
      if (url.startsWith("./api/hosts")) {
        return { ok: true, json: async () => sampleHosts } as Response;
      }
      if (url.startsWith("./api/events")) {
        const parsed = new URL(url, "http://localhost");
        const host = parsed.searchParams.get("host");
        const items = host
          ? sampleEvents.items.filter((ev) => ev.host === host)
          : sampleEvents.items;
        return {
          ok: true,
          json: async () => ({
            items,
            total: items.length,
            page: 1,
            page_size: 50,
          }),
        } as Response;
      }
      return { ok: false, status: 404, json: async () => ({ error: "not found" }) } as Response;
    });
    vi.stubGlobal("fetch", fetchMock);
    return fetchMock;
  }

  it("renders summary, hosts, and events and supports host filtering", async () => {
    const fetchMock = mockFetchSuccess();
    const app = createApp(App);
    app.mount(container);

    await flushPromises();
    await nextTick();

    expect(container.textContent).toContain("CaddyPAW Security Dashboard");
    expect(container.textContent).toContain("203.0.113.10");
    expect(container.textContent).toContain("198.51.100.42");
    expect(container.textContent).toContain("waf:942100");

    // Click Top Subdomains button for app.example.com
    const hostButtons = Array.from(container.querySelectorAll("button")).filter((btn) =>
      btn.textContent?.includes("app.example.com"),
    );
    expect(hostButtons.length).toBeGreaterThan(0);
    hostButtons[0].click();

    await flushPromises();
    await nextTick();

    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining("host=app.example.com"),
      expect.any(Object),
    );
    expect(container.textContent).toContain("203.0.113.10");
    expect(container.textContent).not.toContain("198.51.100.42");

    // Clear filters
    const clearBtn = Array.from(container.querySelectorAll("button")).find(
      (btn) => btn.textContent?.trim() === "Clear Filters",
    );
    expect(clearBtn).toBeDefined();
    clearBtn?.click();

    await flushPromises();
    await nextTick();
    expect(container.textContent).toContain("198.51.100.42");

    app.unmount();
  });

  it("opens event detail modal when clicking a table row", async () => {
    mockFetchSuccess();
    const app = createApp(App);
    app.mount(container);

    await flushPromises();
    await nextTick();

    const rows = container.querySelectorAll("tbody tr");
    expect(rows.length).toBe(2);
    (rows[0] as HTMLTableRowElement).click();
    await nextTick();

    const dialog = container.querySelector("dialog");
    expect(dialog?.hasAttribute("open")).toBe(true);
    expect(dialog?.textContent).toContain("Event #101");
    expect(dialog?.textContent).toContain("AS12345 ExampleNet");

    app.unmount();
  });

  it("filters by action, exact IP from modal, and changes page size", async () => {
    const fetchMock = mockFetchSuccess();
    mountApp();

    await flushPromises();
    await nextTick();

    // Action filter
    const actionSelect = container.querySelector(
      'select[aria-label="Filter by action"]',
    ) as HTMLSelectElement;
    actionSelect.value = "ban";
    actionSelect.dispatchEvent(new Event("change"));
    await flushPromises();
    await nextTick();

    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining("action=ban"),
      expect.any(Object),
    );

    // Open modal and click "Filter IP"
    const firstRow = container.querySelector("tbody tr") as HTMLTableRowElement;
    firstRow.click();
    await nextTick();

    const filterIpBtn = Array.from(container.querySelectorAll("button")).find(
      (b) => b.textContent?.trim() === "Filter IP",
    );
    expect(filterIpBtn).toBeDefined();
    filterIpBtn?.click();
    await flushPromises();
    await nextTick();

    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining("ip=203.0.113.10"),
      expect.any(Object),
    );
    expect(container.textContent).toContain("Exact IP filter:");

    // Change page size
    const pageSizeSelect = container.querySelector(
      'select[aria-label="Page size"]',
    ) as HTMLSelectElement;
    pageSizeSelect.value = "100";
    pageSizeSelect.dispatchEvent(new Event("change"));
    await flushPromises();
    await nextTick();

    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining("page_size=100"),
      expect.any(Object),
    );
  });

  it("renders untrusted XSS payloads safely as text without executing HTML", async () => {
    const xssPayload = `" onmouseover="alert(1)"><img src=x onerror="alert(1)"><script>alert(2)</script>`;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async (input) => {
        const url = String(input);
        if (url.startsWith("./api/summary")) {
          return {
            ok: true,
            json: async () => ({
              total: 1,
              counted: 1,
              ban: 0,
              observed: 0,
              top_hosts: [{ host: xssPayload, count: 1 }],
              top_reasons: [{ reason: xssPayload, count: 1 }],
            }),
          } as Response;
        }
        if (url.startsWith("./api/hosts")) {
          return { ok: true, json: async () => ({ hosts: [] }) } as Response;
        }
        return {
          ok: true,
          json: async () => ({
            items: [
              {
                ...sampleEvents.items[0],
                host: xssPayload,
                path: xssPayload,
                reason: xssPayload,
              },
            ],
            total: 1,
            page: 1,
            page_size: 50,
          }),
        } as Response;
      }),
    );

    mountApp();

    await flushPromises();
    await nextTick();

    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("[onerror],[onmouseover]")).toBeNull();
    expect(container.textContent).toContain(xssPayload);
  });

  it("shows error alert and dashes in summary when API request fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>().mockResolvedValue({
        ok: false,
        status: 500,
        json: async () => ({ error: "failed to query events" }),
      } as Response),
    );

    const app = createApp(App);
    app.mount(container);

    await flushPromises();
    await nextTick();

    const alert = container.querySelector('[role="alert"]');
    expect(alert?.textContent).toContain("failed to query events");
    expect(container.textContent).toContain("Failed to load security events.");

    app.unmount();
  });

  it("toggles light/dark theme and persists to localStorage", async () => {
    mockFetchSuccess();
    const app = createApp(App);
    app.mount(container);

    await flushPromises();
    await nextTick();

    const themeBtn = container.querySelector(
      'button[aria-label="Switch to light theme"]',
    ) as HTMLButtonElement | null;
    expect(themeBtn).not.toBeNull();
    themeBtn?.click();
    await nextTick();

    expect(document.documentElement.getAttribute("data-theme")).toBe("light");
    expect(localStorage.getItem("caddypaw-theme")).toBe("light");

    app.unmount();
  });
});
