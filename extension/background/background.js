// Мост background: слушатели синхронно (требование event page), логика — в WASM.
// Подключение к мосту при каждом запуске фона; onStartup будит фон вместе с Firefox.
import init, { on_connect, on_command, start_bridge } from "../pkg/leash.js";

const ready = init();
ready.then(() => start_bridge());
browser.runtime.onStartup.addListener(() => {});
browser.runtime.onConnect.addListener((port) => ready.then(() => on_connect(port), () => port.disconnect()));
browser.commands.onCommand.addListener((name) => ready.then(() => on_command(name)));

// Операция content-скрипта в главном фрейме (docs/content-contract.md); файл идемпотентен.
globalThis.leashInTab = (tabId, op) => {
  const target = { tabId, frameIds: [0] };
  return browser.scripting.executeScript({ target, files: ["/content/content.js"] })
    .then(() => browser.scripting.executeScript({ target, func: (o) => globalThis.leashRun(o), args: [op] }))
    .then((results) => results[0].result);
};
