#!/bin/sh
# Статические запреты. Любое совпадение валит сборку.
set -u
cd "$(dirname "$0")/.."

fail=0
deny() {
	what=$1; pattern=$2; shift 2
	if grep -rnE "$pattern" "$@"; then
		echo "ЗАПРЕЩЕНО ($what)"; fail=1
	fi
}

OURS="crates/agent crates/core extension/background extension/sidebar extension/options extension/confirm extension/content extension/manifest.json"
HTML="extension/sidebar extension/options extension/confirm"

deny "вставка HTML в DOM" \
	'inner_html|outer_html|insert_adjacent_html|innerHTML|outerHTML|insertAdjacentHTML|document\.write|DOMParser|DomParser|createContextualFragment' $OURS
deny "исполнение строк как кода" \
	'(^|[^A-Za-z_])eval[ (]|new Function|new_with_args|new_no_args|set_(timeout|interval)_with_str|js_name[[:space:]]*=[[:space:]]*"?(eval|Function)' $OURS
deny "исполнение строк как кода в клее" '(^|[^A-Za-z_])eval[ (]|new Function|Function\(' extension/pkg
deny "unsafe в Rust" 'unsafe[[:space:]]*(\{|fn|impl|trait|extern)' crates
JS="extension/background extension/sidebar extension/options extension/confirm extension/content"
# В JS-мосте запрещено само слово: ловит и console.log, и `const {log} = console`.
deny "логи в консоль (утечка данных)" '(^|[^A-Za-z0-9_$])console([^A-Za-z0-9_$]|$)' $JS
# В Rust к консоли можно прийти только через привязку: web-sys или своя extern.
deny "логи в консоль из Rust" 'web_sys::console|js_namespace[[:space:]]*=[[:space:]]*\[?[[:space:]]*"?console|js_name[[:space:]]*=[[:space:]]*"?(log|warn|error|info|debug)"?' crates
deny "хранилища страницы" 'localStorage|sessionStorage|indexedDB|document\.cookie' $OURS
deny "inline-стили и обработчики в HTML" '<style|style[[:space:]]*=|[[:space:]]on[a-z]+[[:space:]]*=' $HTML
deny "внешние адреса в HTML/CSS" 'https?://|//[a-z0-9.-]+\.[a-z]' $HTML extension/ui.css

# Content-скрипт исполняется в чужой вкладке: никаких API расширения, сети,
# сообщений, таймеров и навигации (docs/content-contract.md).
CONTENT="extension/content"
deny "API расширения в content-скрипте" '(^|[^A-Za-z0-9_$])(browser|chrome|runtime)[[:space:]]*(\.|\[)' $CONTENT
deny "сеть и сообщения в content-скрипте" 'fetch|XMLHttpRequest|WebSocket|EventSource|sendBeacon|postMessage|addEventListener|onmessage|import[[:space:]]*\(|importScripts|Worker' $CONTENT
deny "таймеры и навигация в content-скрипте" 'setTimeout|setInterval|requestAnimationFrame|location[[:space:]]*(=[^=]|\.(assign|replace|href[[:space:]]*=[^=]))|window\.open|(^|[^A-Za-z0-9_.])open[[:space:]]*\(|\.submit[[:space:]]*\(|cookie' $CONTENT
# Значение файла — результат executeScript({files}); функция не клонируется,
# и тогда браузер отклоняет весь вызов (страница не читается вовсе).
if ! tail -n 1 $CONTENT/content.js | grep -q "^undefined;"; then
	echo "ЗАПРЕЩЕНО (content.js должен заканчиваться строкой undefined;)"; fail=1
fi
# Скрипт внедряется только в изолированный мир.
deny "внедрение в мир страницы" 'MAIN|world[[:space:]]*:' extension/background

# Каждый <script> в HTML обязан быть внешним (с src) и с пустым телом.
if grep -rn '<script' $HTML | grep -vE '<script type="module" src="[a-z]+\.js"></script>'; then
	echo "ЗАПРЕЩЕНО (inline-скрипт или нестандартный <script>)"; fail=1
fi

# Клей wasm-bindgen: допускается ровно один fetch — загрузка своего .wasm.
# Сети у расширения нет: страницы уходят только в мост.
unknown_fetch=$(grep -nE 'fetch\(' extension/pkg/leash.js \
	| grep -vE 'module_or_path = fetch\(module_or_path\);$')
if [ -n "$unknown_fetch" ]; then echo "неизвестный fetch в клее:"; echo "$unknown_fetch"; fail=1; fi
fetches=$(grep -oE 'fetch\(' extension/pkg/leash.js | wc -l | tr -d ' ')
if [ "$fetches" -ne 1 ]; then echo "в клее $fetches вызовов fetch, ожидается 1"; fail=1; fi
deny "иные сетевые API в клее" 'XMLHttpRequest|WebSocket|sendBeacon|EventSource|importScripts|import\(' extension/pkg
# В клее допустим только console.warn о загрузке wasm и устаревших параметрах.
deny "логи в клее" 'console\.(log|info|debug|error|trace|dir|table)' extension/pkg
warns=$(grep -oE 'console\.warn' extension/pkg/leash.js | wc -l | tr -d ' ')
if [ "$warns" -gt 3 ]; then echo "в клее $warns console.warn, ожидается не больше 3"; fail=1; fi

# Бюджет JS-моста: суммарно не больше 200 строк.
js_lines=$(cat extension/background/*.js extension/sidebar/*.js extension/options/*.js extension/confirm/*.js extension/content/*.js | wc -l | tr -d ' ')
if [ "$js_lines" -gt 200 ]; then echo "JS-мост $js_lines строк, лимит 200"; fail=1; fi

[ "$fail" -eq 0 ] && echo "check-static: ok (JS-мост: $js_lines строк)"
exit "$fail"
