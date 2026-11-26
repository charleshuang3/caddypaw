<script setup lang="ts">
import {
  actionBadgeClass,
  formatGeoLocation,
  formatLocalDateTime,
  formatRelativeTime,
  isWafReason,
  methodBadgeClass,
  splitReasons,
} from "../lib/format";
import type { SecurityEvent } from "../types/security";

defineProps<{
  events: SecurityEvent[];
  loading: boolean;
  hasError: boolean;
}>();

const emit = defineEmits<{
  (e: "selectEvent", event: SecurityEvent): void;
}>();
</script>

<template>
  <div class="card bg-base-100 border border-base-300 shadow-sm overflow-hidden">
    <div class="overflow-x-auto">
      <table class="table table-sm table-zebra w-full">
        <thead>
          <tr>
            <th>Time</th>
            <th>Subdomain</th>
            <th>IP &amp; Geo</th>
            <th>Request</th>
            <th>Reason</th>
            <th class="text-right">Weight</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="loading && events.length === 0">
            <td colspan="7" class="text-center py-10">
              <span class="loading loading-spinner loading-md text-primary"></span>
              <div class="text-sm text-base-content/60 mt-2">Loading security events...</div>
            </td>
          </tr>
          <tr v-else-if="hasError && events.length === 0">
            <td colspan="7" class="text-center py-10 text-error">
              Failed to load security events.
            </td>
          </tr>
          <tr v-else-if="events.length === 0">
            <td colspan="7" class="text-center py-10 text-base-content/60">
              No security events match the current filters.
            </td>
          </tr>
          <tr
            v-for="ev in events"
            v-else
            :key="ev.id"
            class="hover cursor-pointer"
            tabindex="0"
            @click="emit('selectEvent', ev)"
            @keydown.enter.prevent="emit('selectEvent', ev)"
            @keydown.space.prevent="emit('selectEvent', ev)"
          >
            <td class="whitespace-nowrap">
              <div class="font-medium text-xs" :title="ev.created_at">
                {{ formatRelativeTime(ev.created_at) }}
              </div>
              <div class="text-[11px] text-base-content/60">
                {{ formatLocalDateTime(ev.created_at) }}
              </div>
            </td>

            <td class="whitespace-nowrap">
              <span v-if="ev.host" class="badge badge-sm badge-outline font-mono">
                {{ ev.host }}
              </span>
              <span v-else class="text-base-content/40">—</span>
            </td>

            <td>
              <div class="font-mono text-xs font-semibold">{{ ev.ip }}</div>
              <div class="text-[11px] text-base-content/60">
                {{ formatGeoLocation(ev) }}
                <span v-if="ev.asn" class="ml-1 opacity-80">· {{ ev.asn }}</span>
              </div>
            </td>

            <td class="max-w-xs">
              <div class="flex items-center gap-1.5">
                <span
                  v-if="ev.method"
                  class="badge badge-xs font-mono shrink-0"
                  :class="methodBadgeClass(ev.method)"
                >
                  {{ ev.method }}
                </span>
                <span class="font-mono text-xs truncate" :title="ev.path || '—'">
                  {{ ev.path || "—" }}
                </span>
              </div>
            </td>

            <td class="max-w-sm">
              <div v-if="splitReasons(ev.reason).length === 0" class="text-base-content/40">—</div>
              <div v-else class="flex flex-wrap gap-1">
                <span
                  v-for="(r, idx) in splitReasons(ev.reason)"
                  :key="`${ev.id}-r-${idx}`"
                  class="badge badge-xs font-mono"
                  :class="isWafReason(r) ? 'badge-secondary' : 'badge-ghost'"
                  :title="r"
                >
                  {{ r }}
                </span>
              </div>
            </td>

            <td class="text-right font-mono text-xs">
              {{ ev.weight }}
            </td>

            <td class="whitespace-nowrap">
              <span class="badge badge-sm font-medium" :class="actionBadgeClass(ev.action)">
                {{ ev.action }}
              </span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
