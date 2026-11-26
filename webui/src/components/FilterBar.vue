<script setup lang="ts">
import { computed } from "vue";
import type { EventActionFilter, HostEventCount } from "../types/security";

const props = defineProps<{
  hosts: HostEventCount[];
  selectedHost: string;
  selectedIp: string;
  selectedAction: EventActionFilter;
  searchQuery: string;
}>();

const emit = defineEmits<{
  (e: "update:selectedHost", value: string): void;
  (e: "update:selectedIp", value: string): void;
  (e: "update:selectedAction", value: EventActionFilter): void;
  (e: "update:searchQuery", value: string): void;
  (e: "clear"): void;
}>();

const hasActiveFilters = computed(
  () =>
    props.selectedHost !== "" ||
    props.selectedIp !== "" ||
    props.selectedAction !== "" ||
    props.searchQuery.trim() !== "",
);

const hostMissingFromList = computed(
  () => props.selectedHost !== "" && !props.hosts.some((h) => h.host === props.selectedHost),
);

function onHostChange(event: Event) {
  emit("update:selectedHost", (event.target as HTMLSelectElement).value);
}

function onActionChange(event: Event) {
  emit("update:selectedAction", (event.target as HTMLSelectElement).value as EventActionFilter);
}

function onSearchInput(event: Event) {
  emit("update:searchQuery", (event.target as HTMLInputElement).value);
}
</script>

<template>
  <section
    aria-label="Event filters"
    class="card bg-base-100 border border-base-300 shadow-sm p-3 sm:p-4"
  >
    <div class="flex flex-col md:flex-row gap-3 items-stretch md:items-center">
      <div class="form-control w-full md:w-56">
        <select
          class="select select-sm select-bordered w-full"
          aria-label="Filter by subdomain"
          :value="selectedHost"
          @change="onHostChange"
        >
          <option value="">All Hosts</option>
          <option v-if="hostMissingFromList" :value="selectedHost">{{ selectedHost }} (0)</option>
          <option v-for="h in hosts" :key="h.host" :value="h.host">
            {{ h.host }} ({{ h.count }})
          </option>
        </select>
      </div>

      <div class="form-control w-full md:w-44">
        <select
          class="select select-sm select-bordered w-full"
          aria-label="Filter by action"
          :value="selectedAction"
          @change="onActionChange"
        >
          <option value="">All Actions</option>
          <option value="count error">count error</option>
          <option value="ban">ban</option>
          <option value="banned">banned</option>
          <option value="observed">observed</option>
        </select>
      </div>

      <div class="form-control flex-1">
        <label class="input input-sm input-bordered flex items-center gap-2 w-full">
          <svg
            xmlns="http://www.w3.org/2000/svg"
            class="h-4 w-4 opacity-50 shrink-0"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            stroke-width="2"
            aria-hidden="true"
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
            />
          </svg>
          <input
            type="search"
            class="grow"
            placeholder="Search IP, reason, path, or host..."
            aria-label="Search events"
            :value="searchQuery"
            @input="onSearchInput"
          />
        </label>
      </div>

      <button
        type="button"
        class="btn btn-sm btn-ghost border border-base-300"
        :disabled="!hasActiveFilters"
        @click="emit('clear')"
      >
        Clear Filters
      </button>
    </div>

    <div v-if="selectedIp" class="flex items-center gap-2 pt-2 text-xs">
      <span class="text-base-content/60">Exact IP filter:</span>
      <span class="badge badge-sm badge-primary gap-1 font-mono">
        {{ selectedIp }}
        <button
          type="button"
          class="ml-1 hover:text-error"
          aria-label="Clear IP filter"
          @click="emit('update:selectedIp', '')"
        >
          ✕
        </button>
      </span>
    </div>
  </section>
</template>
