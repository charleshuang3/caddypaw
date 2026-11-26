<script setup lang="ts">
import type { TimeRangeKey } from "../types/security";

defineProps<{
  timeRange: TimeRangeKey;
  autoRefresh: boolean;
  loading: boolean;
  theme: "light" | "dark";
}>();

const emit = defineEmits<{
  (e: "update:timeRange", value: TimeRangeKey): void;
  (e: "update:autoRefresh", value: boolean): void;
  (e: "refresh"): void;
  (e: "toggleTheme"): void;
}>();

const timeRangeOptions: { value: TimeRangeKey; label: string }[] = [
  { value: "1h", label: "Last 1 hour" },
  { value: "24h", label: "Last 24 hours" },
  { value: "7d", label: "Last 7 days" },
  { value: "30d", label: "Last 30 days" },
];

function onRangeChange(event: Event) {
  const target = event.target as HTMLSelectElement;
  emit("update:timeRange", target.value as TimeRangeKey);
}

function onAutoRefreshChange(event: Event) {
  const target = event.target as HTMLInputElement;
  emit("update:autoRefresh", target.checked);
}
</script>

<template>
  <header class="navbar bg-base-100 border-b border-base-300 px-4 lg:px-6 gap-3 flex-wrap">
    <div class="flex-1 min-w-0 flex items-center gap-3">
      <div class="p-2 rounded-lg bg-primary/10 text-primary shrink-0" aria-hidden="true">
        <svg
          xmlns="http://www.w3.org/2000/svg"
          class="h-6 w-6"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          stroke-width="2"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            d="M12 3l7 4v5c0 5-3.5 9-7 10-3.5-1-7-5-7-10V7l7-4z"
          />
          <path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4" />
        </svg>
      </div>
      <div class="min-w-0">
        <h1 class="text-lg font-bold tracking-tight truncate">CaddyPAW Security Dashboard</h1>
        <p class="text-xs text-base-content/60 hidden sm:block">WAF &amp; Firewall Event Monitor</p>
      </div>
    </div>

    <div class="flex items-center gap-2 flex-wrap">
      <select
        class="select select-sm select-bordered w-36"
        aria-label="Time range"
        :value="timeRange"
        @change="onRangeChange"
      >
        <option v-for="opt in timeRangeOptions" :key="opt.value" :value="opt.value">
          {{ opt.label }}
        </option>
      </select>

      <label
        class="label cursor-pointer gap-2 px-2 py-1 rounded-lg border border-base-300 bg-base-200/40"
      >
        <input
          type="checkbox"
          class="toggle toggle-xs toggle-primary"
          aria-label="Auto-refresh every 10 seconds"
          :checked="autoRefresh"
          @change="onAutoRefreshChange"
        />
        <span class="label-text text-xs font-medium whitespace-nowrap">Auto 10s</span>
      </label>

      <button
        type="button"
        class="btn btn-sm btn-ghost border border-base-300"
        aria-label="Refresh dashboard"
        :disabled="loading"
        @click="emit('refresh')"
      >
        <span v-if="loading" class="loading loading-spinner loading-xs" aria-hidden="true"></span>
        <svg
          v-else
          xmlns="http://www.w3.org/2000/svg"
          class="h-4 w-4"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          stroke-width="2"
          aria-hidden="true"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
          />
        </svg>
        <span class="hidden sm:inline">Refresh</span>
      </button>

      <button
        type="button"
        class="btn btn-sm btn-ghost btn-square border border-base-300"
        :aria-label="theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'"
        :title="theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'"
        @click="emit('toggleTheme')"
      >
        <svg
          v-if="theme === 'dark'"
          xmlns="http://www.w3.org/2000/svg"
          class="h-4 w-4"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          stroke-width="2"
          aria-hidden="true"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"
          />
        </svg>
        <svg
          v-else
          xmlns="http://www.w3.org/2000/svg"
          class="h-4 w-4"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          stroke-width="2"
          aria-hidden="true"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"
          />
        </svg>
      </button>
    </div>
  </header>
</template>
