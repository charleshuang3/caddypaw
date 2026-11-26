<script setup lang="ts">
import { isWafReason } from "../lib/format";
import type { SecurityEventSummary } from "../types/security";

defineProps<{
  summary: SecurityEventSummary | null;
  selectedHost: string;
  loading: boolean;
  hasError: boolean;
}>();

const emit = defineEmits<{
  (e: "selectHost", host: string): void;
}>();
</script>

<template>
  <section aria-label="Security summary" class="space-y-4">
    <div
      class="stats stats-vertical sm:stats-horizontal shadow-sm bg-base-100 border border-base-300 w-full"
    >
      <div class="stat">
        <div class="stat-title">Total Events</div>
        <div class="stat-value text-2xl">
          {{ summary ? summary.total.toLocaleString() : loading ? "…" : hasError ? "—" : "0" }}
        </div>
        <div class="stat-desc">Recorded in selected window</div>
      </div>

      <div class="stat">
        <div class="stat-title">Counted Errors</div>
        <div class="stat-value text-2xl text-warning">
          {{ summary ? summary.counted.toLocaleString() : loading ? "…" : hasError ? "—" : "0" }}
        </div>
        <div class="stat-desc">Contributing to ban threshold</div>
      </div>

      <div class="stat">
        <div class="stat-title">Bans</div>
        <div class="stat-value text-2xl text-error">
          {{ summary ? summary.ban.toLocaleString() : loading ? "…" : hasError ? "—" : "0" }}
        </div>
        <div class="stat-desc">Active IP bans triggered</div>
      </div>

      <div class="stat">
        <div class="stat-title">Observed Only</div>
        <div class="stat-value text-2xl text-info">
          {{ summary ? summary.observed.toLocaleString() : loading ? "…" : hasError ? "—" : "0" }}
        </div>
        <div class="stat-desc">Dry-run / observe mode</div>
      </div>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <div class="card bg-base-100 border border-base-300 shadow-sm">
        <div class="card-body p-4">
          <div class="flex items-center justify-between gap-2">
            <h2 class="card-title text-sm font-semibold">Top Subdomains</h2>
            <span class="text-xs text-base-content/60">Click to filter</span>
          </div>
          <div
            v-if="!summary || summary.top_hosts.length === 0"
            class="text-sm text-base-content/50 py-2"
          >
            No host activity in this time range.
          </div>
          <div v-else class="flex flex-wrap gap-2 pt-1">
            <button
              v-for="item in summary.top_hosts"
              :key="item.host"
              type="button"
              class="btn btn-xs gap-1.5"
              :class="selectedHost === item.host ? 'btn-primary' : 'btn-outline border-base-300'"
              :aria-pressed="selectedHost === item.host"
              @click="emit('selectHost', selectedHost === item.host ? '' : item.host)"
            >
              <span class="font-mono">{{ item.host }}</span>
              <span class="badge badge-xs badge-ghost">{{ item.count }}</span>
            </button>
          </div>
        </div>
      </div>

      <div class="card bg-base-100 border border-base-300 shadow-sm">
        <div class="card-body p-4">
          <h2 class="card-title text-sm font-semibold">Top Reasons</h2>
          <div
            v-if="!summary || summary.top_reasons.length === 0"
            class="text-sm text-base-content/50 py-2"
          >
            No reasons recorded in this time range.
          </div>
          <div v-else class="flex flex-wrap gap-2 pt-1">
            <div
              v-for="item in summary.top_reasons"
              :key="item.reason"
              class="badge badge-md gap-1.5 max-w-full"
              :class="isWafReason(item.reason) ? 'badge-secondary badge-outline' : 'badge-ghost'"
              :title="item.reason"
            >
              <span class="truncate max-w-64 font-mono text-xs">{{ item.reason }}</span>
              <span class="font-semibold">{{ item.count }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>
</template>
