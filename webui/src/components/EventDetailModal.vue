<script setup lang="ts">
import { ref, watch } from "vue";
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

const props = defineProps<{
  event: SecurityEvent | null;
}>();

const emit = defineEmits<{
  (e: "close"): void;
  (e: "filterByHost", host: string): void;
  (e: "filterByIp", ip: string): void;
}>();

const dialogRef = ref<HTMLDialogElement | null>(null);

watch(
  () => props.event,
  (val) => {
    const dlg = dialogRef.value;
    if (!dlg) return;
    if (val) {
      if (!dlg.open) {
        dlg.showModal();
      }
    } else if (dlg.open) {
      dlg.close();
    }
  },
  { flush: "post" },
);

function onDialogClose() {
  if (props.event !== null) {
    emit("close");
  }
}

function handleFilterHost(host: string) {
  emit("filterByHost", host);
  emit("close");
}

function handleFilterIp(ip: string) {
  emit("filterByIp", ip);
  emit("close");
}
</script>

<template>
  <dialog ref="dialogRef" class="modal" aria-label="Security event details" @close="onDialogClose">
    <div v-if="event" class="modal-box max-w-2xl">
      <div class="flex items-start justify-between gap-4 pb-3 border-b border-base-300">
        <div>
          <h3 class="font-bold text-lg flex items-center gap-2">
            Event #{{ event.id }}
            <span class="badge badge-sm" :class="actionBadgeClass(event.action)">
              {{ event.action }}
            </span>
            <span v-if="event.observed" class="badge badge-sm badge-info badge-outline">
              observed
            </span>
          </h3>
          <p class="text-xs text-base-content/60 mt-0.5">
            {{ formatLocalDateTime(event.created_at) }} ({{ formatRelativeTime(event.created_at) }})
          </p>
        </div>
        <button
          type="button"
          class="btn btn-sm btn-circle btn-ghost"
          aria-label="Close modal"
          @click="emit('close')"
        >
          ✕
        </button>
      </div>

      <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 py-4 text-sm">
        <div>
          <div class="text-xs uppercase tracking-wide text-base-content/60">IP Address</div>
          <div class="font-mono font-semibold mt-0.5 flex items-center gap-2">
            <span>{{ event.ip }}</span>
            <button
              type="button"
              class="btn btn-xs btn-ghost border border-base-300"
              @click="handleFilterIp(event.ip)"
            >
              Filter IP
            </button>
          </div>
        </div>

        <div>
          <div class="text-xs uppercase tracking-wide text-base-content/60">Subdomain (Host)</div>
          <div class="font-mono mt-0.5 flex items-center gap-2">
            <span>{{ event.host || "—" }}</span>
            <button
              v-if="event.host"
              type="button"
              class="btn btn-xs btn-ghost border border-base-300"
              @click="handleFilterHost(event.host)"
            >
              Filter Host
            </button>
          </div>
        </div>

        <div>
          <div class="text-xs uppercase tracking-wide text-base-content/60">GeoIP Location</div>
          <div class="mt-0.5">{{ formatGeoLocation(event) }}</div>
        </div>

        <div>
          <div class="text-xs uppercase tracking-wide text-base-content/60">ASN / Organization</div>
          <div class="mt-0.5">{{ event.asn || "—" }}</div>
        </div>

        <div>
          <div class="text-xs uppercase tracking-wide text-base-content/60">Weight</div>
          <div class="font-mono mt-0.5">{{ event.weight }}</div>
        </div>

        <div>
          <div class="text-xs uppercase tracking-wide text-base-content/60">Jail Until</div>
          <div class="mt-0.5">
            <template v-if="event.jail_until">
              {{ formatLocalDateTime(event.jail_until) }}
              <span class="text-xs text-base-content/60">
                ({{ formatRelativeTime(event.jail_until) }})
              </span>
            </template>
            <template v-else>—</template>
          </div>
        </div>

        <div class="sm:col-span-2">
          <div class="text-xs uppercase tracking-wide text-base-content/60">Request</div>
          <div
            class="mt-1 p-2 rounded-lg bg-base-200 font-mono text-xs break-all flex items-center gap-2"
          >
            <span
              v-if="event.method"
              class="badge badge-xs shrink-0"
              :class="methodBadgeClass(event.method)"
            >
              {{ event.method }}
            </span>
            <span>{{ event.path || "—" }}</span>
          </div>
        </div>

        <div class="sm:col-span-2">
          <div class="text-xs uppercase tracking-wide text-base-content/60">Reasons</div>
          <div v-if="splitReasons(event.reason).length === 0" class="mt-1 text-base-content/50">
            —
          </div>
          <div v-else class="mt-1 flex flex-wrap gap-1.5">
            <span
              v-for="(r, idx) in splitReasons(event.reason)"
              :key="`detail-r-${idx}`"
              class="badge badge-sm font-mono"
              :class="isWafReason(r) ? 'badge-secondary' : 'badge-ghost'"
            >
              {{ r }}
            </span>
          </div>
        </div>
      </div>

      <div class="modal-action mt-2">
        <button type="button" class="btn btn-sm" @click="emit('close')">Close</button>
      </div>
    </div>
    <form method="dialog" class="modal-backdrop">
      <button type="submit">close</button>
    </form>
  </dialog>
</template>
