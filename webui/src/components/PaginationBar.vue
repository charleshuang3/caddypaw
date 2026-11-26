<script setup lang="ts">
import { computed } from "vue";

const props = defineProps<{
  page: number;
  pageSize: number;
  total: number;
}>();

const emit = defineEmits<{
  (e: "update:page", value: number): void;
  (e: "update:pageSize", value: number): void;
}>();

const totalPages = computed(() => Math.max(1, Math.ceil(props.total / props.pageSize)));
const effectivePage = computed(() => Math.min(props.page, totalPages.value));
const startItem = computed(() =>
  props.total === 0 ? 0 : (effectivePage.value - 1) * props.pageSize + 1,
);
const endItem = computed(() => Math.min(props.total, effectivePage.value * props.pageSize));

function onPageSizeChange(event: Event) {
  const val = Number((event.target as HTMLSelectElement).value);
  emit("update:pageSize", val);
}
</script>

<template>
  <div class="flex flex-col sm:flex-row items-center justify-between gap-3 py-2 text-sm">
    <div class="text-base-content/70">
      Showing <span class="font-semibold text-base-content">{{ startItem }}–{{ endItem }}</span> of
      <span class="font-semibold text-base-content">{{ total.toLocaleString() }}</span> events
    </div>

    <div class="flex items-center gap-3">
      <label class="flex items-center gap-2 text-xs text-base-content/70">
        <span>Rows:</span>
        <select
          class="select select-xs select-bordered"
          aria-label="Page size"
          :value="pageSize"
          @change="onPageSizeChange"
        >
          <option :value="25">25</option>
          <option :value="50">50</option>
          <option :value="100">100</option>
          <option :value="200">200</option>
        </select>
      </label>

      <div class="join">
        <button
          type="button"
          class="join-item btn btn-xs"
          :disabled="page <= 1"
          aria-label="Previous page"
          @click="emit('update:page', page - 1)"
        >
          « Prev
        </button>
        <span class="join-item btn btn-xs btn-ghost no-animation pointer-events-none">
          Page {{ page }} / {{ totalPages }}
        </span>
        <button
          type="button"
          class="join-item btn btn-xs"
          :disabled="page >= totalPages"
          aria-label="Next page"
          @click="emit('update:page', page + 1)"
        >
          Next »
        </button>
      </div>
    </div>
  </div>
</template>
