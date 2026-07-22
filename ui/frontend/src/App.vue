<script setup lang="ts">
import { ref, onMounted } from "vue";
import { invoke } from "@tauri-apps/api/tauri";

const version = ref("");
const status = ref("Initializing...");
const devices = ref<string[]>([]);

onMounted(async () => {
  version.value = await invoke("get_version");
  status.value = "Ready";
});
</script>

<template>
  <div class="container">
    <header>
      <h1>IP6Desk</h1>
      <p class="subtitle">P2P Remote Desktop — IPv6 + Zero Trust</p>
      <span class="version">v{{ version }}</span>
    </header>

    <main>
      <section class="device-list">
        <h2>Devices</h2>
        <div v-if="devices.length === 0" class="empty">
          No devices connected. Enter a device ID to connect.
        </div>
        <div v-for="d in devices" :key="d" class="device-item">
          {{ d }}
        </div>
      </section>

      <section class="connect-panel">
        <h2>Connect</h2>
        <input type="text" placeholder="Device ID (e.g. my-pc)" />
        <button>Connect</button>
      </section>
    </main>

    <footer>
      <span class="status">{{ status }}</span>
    </footer>
  </div>
</template>

<style>
:root {
  --bg: #0d1117;
  --fg: #c9d1d9;
  --accent: #58a6ff;
  --border: #30363d;
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: var(--bg);
  color: var(--fg);
  height: 100vh;
}

.container {
  display: flex; flex-direction: column; height: 100vh; padding: 1rem;
}

header {
  border-bottom: 1px solid var(--border);
  padding-bottom: 0.5rem; margin-bottom: 1rem;
}

h1 { color: var(--accent); font-size: 1.5rem; }
.subtitle { font-size: 0.85rem; opacity: 0.7; }
.version { font-size: 0.75rem; opacity: 0.5; }

main {
  flex: 1; display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;
}

section {
  border: 1px solid var(--border); border-radius: 6px; padding: 1rem;
}

h2 { font-size: 1rem; margin-bottom: 0.5rem; }

.empty { font-size: 0.85rem; opacity: 0.5; font-style: italic; }

.connect-panel input {
  width: 100%; padding: 0.5rem; margin-bottom: 0.5rem;
  background: #161b22; border: 1px solid var(--border);
  border-radius: 4px; color: var(--fg);
}

.connect-panel button {
  padding: 0.5rem 1rem; background: var(--accent);
  border: none; border-radius: 4px; color: #fff; cursor: pointer;
}

footer {
  border-top: 1px solid var(--border);
  padding-top: 0.5rem; margin-top: 1rem;
  font-size: 0.8rem; opacity: 0.6;
}
</style>
