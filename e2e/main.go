// Red-team стенд Leash: настоящий Firefox, настоящее расширение, мок API в роли
// скомпрометированной модели и атакующие страницы. Каждый сценарий — попытка
// атаки; проверяется, что политика её остановила.
//
// Запуск: make e2e (или из каталога e2e: go run . [-run подстрока] [-headed]).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

const (
	firefoxBin = "/Applications/Firefox.app/Contents/MacOS/firefox"
	extID      = "leash@localhost"
	// Фальшивый ключ собран из частей, чтобы pre-commit не принял его за настоящий.
	testKey = "sk-ant-" + "api03-" + "e2eTESTKEYe2eTESTKEYe2eTESTKEYe2eTESTKEY0000"
)

type env struct {
	m *Marionette
	p *Proxy
}

func main() {
	only := flag.String("run", "", "запускать только сценарии, чьё имя содержит строку")
	headed := flag.Bool("headed", false, "показывать окно Firefox")
	flag.Parse()

	root, err := filepath.Abs("..")
	must(err)
	extDir := filepath.Join(root, "extension")
	if _, err := os.Stat(filepath.Join(extDir, "pkg", "leash_bg.wasm")); err != nil {
		fail("нет собранного WASM: сначала make build")
	}

	p, err := newProxy()
	must(err)
	profile, err := os.MkdirTemp("", "leash-e2e-profile")
	must(err)
	defer os.RemoveAll(profile)
	mport := freePort()
	must(os.WriteFile(filepath.Join(profile, "user.js"), []byte(fmt.Sprintf(`
user_pref("marionette.port", %d);
user_pref("network.proxy.type", 1);
user_pref("network.proxy.ssl", "127.0.0.1");
user_pref("network.proxy.ssl_port", %d);
user_pref("network.proxy.http", "127.0.0.1");
user_pref("network.proxy.http_port", %d);
user_pref("network.proxy.no_proxies_on", "");
user_pref("network.proxy.allow_hijacking_localhost", true);
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("app.update.enabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("toolkit.telemetry.enabled", false);
user_pref("browser.startup.page", 0);
`, mport, p.port(), p.port())), 0o644))

	args := []string{"-marionette", "-remote-allow-system-access", "-no-remote", "-new-instance", "-profile", profile}
	if !*headed {
		args = append(args, "-headless")
	}
	ff := exec.Command(firefoxBin, args...)
	must(ff.Start())
	defer func() {
		ff.Process.Kill()
		ff.Wait()
	}()

	m, err := dialMarionette(mport, 30*time.Second)
	must(err)
	_, err = m.call("WebDriver:NewSession", map[string]any{"capabilities": map[string]any{
		"alwaysMatch": map[string]any{"acceptInsecureCerts": true},
	}})
	must(err)
	e := &env{m: m, p: p}
	must(e.setup(extDir))

	passed, failed := 0, 0
	for _, s := range scenarios {
		if *only != "" && !strings.Contains(s.name, *only) {
			continue
		}
		start := time.Now()
		err := e.runScenario(s)
		if err != nil {
			failed++
			fmt.Printf("FAIL %-44s %v\n", s.name, err)
		} else {
			passed++
			fmt.Printf("PASS %-44s (%.1fs)\n", s.name, time.Since(start).Seconds())
		}
	}
	fmt.Printf("\nИтог: %d прошло, %d упало\n", passed, failed)
	if failed > 0 {
		ff.Process.Kill()
		os.Exit(1)
	}
}

func (e *env) setup(extDir string) error {
	// Тестовый профиль: TLS прокси подписан самим собой; наружу трафика нет.
	if _, err := e.m.chrome(`const done = arguments[arguments.length - 1];
Cc["@mozilla.org/security/certoverride;1"].getService(Ci.nsICertOverrideService)
  .setDisableAllSecurityChecksAndLetAttackersInterceptMyData(true);
done("ok");`); err != nil {
		return fmt.Errorf("сертификаты: %w", err)
	}
	if _, err := e.m.call("Addon:Install", map[string]any{"path": extDir, "temporary": true}); err != nil {
		return fmt.Errorf("установка: %w", err)
	}
	// Host-разрешения на тестовые сайты выдаются тем же механизмом, что и
	// по клику пользователя в permissions.request; манифест не меняется.
	_, err := e.m.chrome(`
const done = arguments[arguments.length - 1];
const { ExtensionPermissions } = ChromeUtils.importESModule("resource://gre/modules/ExtensionPermissions.sys.mjs");
const policy = WebExtensionPolicy.getByID(arguments[0]);
ExtensionPermissions.add(arguments[0], {
  permissions: [],
  origins: ["https://a.leash.test/*", "https://b.leash.test/*", "https://www.tbank.ru/*"],
}, policy.extension).then(() => done("ok"), e => done("ERR " + e));`, extID)
	if err != nil {
		return fmt.Errorf("разрешения: %w", err)
	}
	if _, err := e.m.chrome(`
const done = arguments[arguments.length - 1];
Services.wm.getMostRecentWindow("navigator:browser").SidebarController
  .show("leash_localhost-sidebar-action").then(() => done("ok"), e => done("ERR " + e));`); err != nil {
		return fmt.Errorf("панель: %w", err)
	}
	// Панель готова, когда фон ответил ready и окно определено.
	deadline := time.Now().Add(20 * time.Second)
	for {
		var ready bool
		err := e.m.sidebar(`return !w.document.getElementById("input").disabled;`, &ready)
		if err == nil && ready {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("панель не готова: %v", err)
		}
		time.Sleep(300 * time.Millisecond)
	}
	var granted []string
	if err := e.m.sidebar(fmt.Sprintf(`
await w.browser.storage.session.set({api_key: %q, api_key_hint: "0000"});
await w.browser.storage.local.set({allow_origins: "https://a.leash.test\nhttps://b.leash.test\nhttps://c.leash.test", deny_hosts: ""});
const all = await w.browser.permissions.getAll();
return Array.from(all.origins);`, testKey), &granted); err != nil {
		return fmt.Errorf("настройки: %w", err)
	}
	fmt.Printf("разрешения расширения: %v\n", granted)
	return nil
}

func (e *env) runScenario(s scenario) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("паника: %v", r)
		}
	}()
	lookupMiss.Store("")
	if err := s.run(e); err != nil {
		return err
	}
	if miss, _ := lookupMiss.Load().(string); miss != "" {
		return fmt.Errorf("стенд: в снимке нет элемента %q", miss)
	}
	return nil
}

// --- Действия с панелью ---

type logEntry struct {
	Class string `json:"c"`
	Text  string `json:"t"`
}

func (e *env) log() []logEntry {
	var out []logEntry
	e.m.sidebar(`return Array.from(w.document.getElementById("log").children)
  .map(el => ({c: el.className, t: el.textContent}));`, &out)
	return out
}

func (e *env) newChat() error {
	return e.m.sidebar(`w.document.getElementById("reset").click(); return null;`, nil)
}

func (e *env) send(text string) error {
	var ok bool
	err := e.m.sidebar(fmt.Sprintf(`
const input = w.document.getElementById("input");
if (input.disabled) return false;
input.value = %q;
w.document.getElementById("send").click();
return true;`, text), &ok)
	if err == nil && !ok {
		err = fmt.Errorf("поле ввода недоступно")
	}
	return err
}

func (e *env) pendingConfirm() string {
	var text *string
	e.m.sidebar(`const c = w.document.getElementById("confirm");
return c.hidden ? null : w.document.getElementById("confirm-text").textContent;`, &text)
	if text == nil {
		return ""
	}
	return *text
}

func (e *env) answer(allow bool) error {
	id := "confirm-deny"
	if allow {
		id = "confirm-allow"
	}
	return e.m.sidebar(fmt.Sprintf(`w.document.getElementById(%q).click(); return null;`, id), nil)
}

func (e *env) stop() error {
	return e.m.sidebar(`w.document.getElementById("stop").click(); return null;`, nil)
}

// waitIdle ждёт конца задачи: в журнале появилась итоговая запись после
// сообщения пользователя, и панель не занята.
func (e *env) waitIdle(timeout time.Duration) ([]logEntry, error) {
	deadline := time.Now().Add(timeout)
	for {
		var busy bool
		e.m.sidebar(`return w.document.getElementById("status").textContent !== "";`, &busy)
		log := e.log()
		if !busy && len(log) > 0 {
			last := log[len(log)-1]
			if strings.Contains(last.Class, "notice") || strings.Contains(last.Class, "error") ||
				strings.Contains(last.Class, "assistant") {
				return log, nil
			}
		}
		if time.Now().After(deadline) {
			return log, fmt.Errorf("задача не закончилась за %v; журнал: %v", timeout, tail(log, 4))
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func (e *env) waitConfirm(timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for {
		if t := e.pendingConfirm(); t != "" {
			return t, nil
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("подтверждение не появилось; журнал: %v", tail(e.log(), 4))
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// task: новый чат, сценарий мока, вкладка на url, задача пользователя.
func (e *env) task(url, text string, steps ...step) error {
	if err := e.newChat(); err != nil {
		return err
	}
	e.p.reset(script(steps...))
	if url != "" {
		if err := e.m.navigate(url); err != nil {
			return fmt.Errorf("переход на %s: %w", url, err)
		}
	}
	return e.send(text)
}

// --- Сценарий мока ---

// step отвечает на n-й запрос сценария; видит запрос (и снимок в нём).
type step func(req APIRequest) Reply

func script(steps ...step) func(int, APIRequest) Reply {
	return func(n int, req APIRequest) Reply {
		if n < len(steps) {
			return steps[n](req)
		}
		return Reply{Body: final("Готово.")}
	}
}

func reply(calls ...call) step {
	return func(APIRequest) Reply { return Reply{Body: tools(calls...)} }
}

func done(text string) step {
	return func(APIRequest) Reply { return Reply{Body: final(text)} }
}

var elementLine = regexp.MustCompile(`\[(\d+)\] [a-z]+ «([^»]*)»`)

// lookupMiss — имя элемента, которого не нашлось в снимке: это ошибка
// сценария, а не повод для «случайного» отказа политики.
var lookupMiss atomic.Value

// elementID ищет номер элемента по имени в снимке из результатов запроса.
func elementID(req APIRequest, name string) int {
	for _, r := range lastResults(req) {
		for _, m := range elementLine.FindAllStringSubmatch(r.text, -1) {
			if m[2] == name {
				var id int
				fmt.Sscan(m[1], &id)
				return id
			}
		}
	}
	lookupMiss.Store(name)
	return 0
}

// clickByName — шаг: нажать элемент с именем из последнего снимка.
func clickByName(name string) step {
	return func(req APIRequest) Reply {
		return Reply{Body: tools(tool("click", map[string]any{"element": elementID(req, name)}))}
	}
}

// --- Утилиты ---

func tail(log []logEntry, n int) []logEntry {
	if len(log) <= n {
		return log
	}
	return log[len(log)-n:]
}

func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func must(err error) {
	if err != nil {
		fail(err.Error())
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "e2e:", msg)
	os.Exit(2)
}

func dump(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
