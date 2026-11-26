<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, watch } from "vue";
import DashboardHeader from "./components/DashboardHeader.vue";
import EventDetailModal from "./components/EventDetailModal.vue";
import EventsTable from "./components/EventsTable.vue";
import FilterBar from "./components/FilterBar.vue";
import PaginationBar from "./components/PaginationBar.vue";
import SummaryCards from "./components/SummaryCards.vue";
import { fetchEvents, fetchHosts, fetchSummary, timeRangeToFromIso } from "./lib/api";
import type {
  EventActionFilter,
  HostEventCount,
  SecurityEvent,
  SecurityEventSummary,
  TimeRangeKey,
} from "./types/security";

const THEME_STORAGE_KEY = "caddypaw-theme";
const AUTO_REFRESH_MS = 10_000;

function readInitialTheme(): "light" | "dark" {
  try {
    const saved = localStorage.getItem(THEME_STORAGE_KEY);
    if (saved === "light" || saved === "dark") {
      return saved;
    }
  } catch {
    // Ignore storage access errors.
  }
  const attr = document.documentElement.getAttribute("data-theme");
  return attr === "light" ? "light" : "dark";
}

const theme = ref<"light" | "dark">(readInitialTheme());
const timeRange = ref<TimeRangeKey>("24h");
const autoRefresh = ref(false);
const selectedHost = ref("");
const selectedIp = ref("");
const selectedAction = ref<EventActionFilter>("");
const searchQuery = ref("");
const page = ref(1);
const pageSize = ref(50);

const events = ref<SecurityEvent[]>([]);
const total = ref(0);
const hosts = ref<HostEventCount[]>([]);
const summary = ref<SecurityEventSummary | null>(null);
const selectedEvent = ref<SecurityEvent | null>(null);

const loading = ref(false);
const errorMessage = ref("");

let activeController: AbortController | null = null;
let refreshTimer: ReturnType<typeof setInterval> | null = null;
let searchDebounceTimer: ReturnType<typeof setTimeout> | null = null;

function applyTheme(next: "light" | "dark") {
  theme.value = next;
  document.documentElement.setAttribute("data-theme", next);
  try {
    localStorage.setItem(THEME_STORAGE_KEY, next);
  } catch {
    // Ignore storage access errors.
  }
}

function toggleTheme() {
  applyTheme(theme.value === "dark" ? "light" : "dark");
}

async function loadDashboardData() {
  if (activeController) {
    activeController.abort();
  }
  const controller = new AbortController();
  activeController = controller;

  loading.value = true;
  errorMessage.value = "";

  const from = timeRangeToFromIso(timeRange.value);

  try {
    const [eventsRes, hostsRes, summaryRes] = await Promise.all([
      fetchEvents(
        {
          from,
          page: page.value,
          page_size: pageSize.value,
          host: selectedHost.value || undefined,
          ip: selectedIp.value || undefined,
          action: selectedAction.value || undefined,
          q: searchQuery.value.trim() || undefined,
        },
        controller.signal,
      ),
      fetchHosts({ from }, controller.signal),
      fetchSummary({ from }, controller.signal),
    ]);

    if (controller.signal.aborted) {
      return;
    }

    if (eventsRes.items.length === 0 && eventsRes.total > 0 && page.value > 1) {
      page.value = Math.max(1, Math.ceil(eventsRes.total / pageSize.value));
      void loadDashboardData();
      return;
    }

    events.value = eventsRes.items;
    total.value = eventsRes.total;
    hosts.value = hostsRes.hosts;
    summary.value = summaryRes;
  } catch (err) {
    if (controller.signal.aborted || (err instanceof DOMException && err.name === "AbortError")) {
      return;
    }
    errorMessage.value = err instanceof Error ? err.message : "Failed to load dashboard data";
  } finally {
    if (activeController === controller) {
      loading.value = false;
    }
  }
}

function resetAndLoad() {
  if (searchDebounceTimer) {
    clearTimeout(searchDebounceTimer);
    searchDebounceTimer = null;
  }
  page.value = 1;
  void loadDashboardData();
}

function clearFilters() {
  selectedHost.value = "";
  selectedIp.value = "";
  selectedAction.value = "";
  searchQuery.value = "";
  resetAndLoad();
}

function onSelectHost(host: string) {
  selectedHost.value = host;
  resetAndLoad();
}

function onSelectAction(action: EventActionFilter) {
  selectedAction.value = action;
  resetAndLoad();
}

function onUpdateSearch(q: string) {
  searchQuery.value = q;
  if (searchDebounceTimer) {
    clearTimeout(searchDebounceTimer);
  }
  searchDebounceTimer = setTimeout(() => {
    resetAndLoad();
  }, 250);
}

function onUpdateTimeRange(range: TimeRangeKey) {
  timeRange.value = range;
  resetAndLoad();
}

function onUpdatePage(nextPage: number) {
  page.value = nextPage;
  void loadDashboardData();
}

function onUpdatePageSize(nextSize: number) {
  pageSize.value = nextSize;
  page.value = 1;
  void loadDashboardData();
}

function onFilterByIp(ip: string) {
  selectedIp.value = ip;
  resetAndLoad();
}

watch(autoRefresh, (enabled) => {
  if (refreshTimer) {
    clearInterval(refreshTimer);
    refreshTimer = null;
  }
  if (enabled) {
    refreshTimer = setInterval(() => {
      if (!loading.value) {
        void loadDashboardData();
      }
    }, AUTO_REFRESH_MS);
  }
});

onMounted(() => {
  applyTheme(theme.value);
  void loadDashboardData();
});

onBeforeUnmount(() => {
  if (activeController) {
    activeController.abort();
  }
  if (refreshTimer) {
    clearInterval(refreshTimer);
  }
  if (searchDebounceTimer) {
    clearTimeout(searchDebounceTimer);
  }
});
</script>

<template>
  <div class="min-h-screen bg-base-200 text-base-content flex flex-col">
    <DashboardHeader
      :time-range="timeRange"
      :auto-refresh="autoRefresh"
      :loading="loading"
      :theme="theme"
      @update:time-range="onUpdateTimeRange"
      @update:auto-refresh="autoRefresh = $event"
      @refresh="loadDashboardData"
      @toggle-theme="toggleTheme"
    />

    <main class="flex-1 container mx-auto max-w-7xl px-4 lg:px-6 py-5 space-y-5">
      <div v-if="errorMessage" role="alert" class="alert alert-error shadow-sm">
        <svg
          xmlns="http://www.w3.org/2000/svg"
          class="h-5 w-5 shrink-0"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          stroke-width="2"
          aria-hidden="true"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            d="M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"
          />
        </svg>
        <span>{{ errorMessage }}</span>
        <button type="button" class="btn btn-xs btn-ghost" @click="loadDashboardData">Retry</button>
      </div>

      <SummaryCards
        :summary="summary"
        :selected-host="selectedHost"
        :loading="loading"
        :has-error="errorMessage !== ''"
        @select-host="onSelectHost"
      />

      <FilterBar
        :hosts="hosts"
        :selected-host="selectedHost"
        :selected-ip="selectedIp"
        :selected-action="selectedAction"
        :search-query="searchQuery"
        @update:selected-host="onSelectHost"
        @update:selected-ip="onFilterByIp"
        @update:selected-action="onSelectAction"
        @update:search-query="onUpdateSearch"
        @clear="clearFilters"
      />

      <EventsTable
        :events="events"
        :loading="loading"
        :has-error="errorMessage !== ''"
        @select-event="selectedEvent = $event"
      />

      <PaginationBar
        :page="page"
        :page-size="pageSize"
        :total="total"
        @update:page="onUpdatePage"
        @update:page-size="onUpdatePageSize"
      />
    </main>

    <EventDetailModal
      :event="selectedEvent"
      @close="selectedEvent = null"
      @filter-by-host="onSelectHost"
      @filter-by-ip="onFilterByIp"
    />
  </div>
</template>
