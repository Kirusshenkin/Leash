// Red-team стенд Leash: настоящий Firefox, настоящее расширение, настоящий мост
// (leash-host), драйвер MCP в роли скомпрометированной модели и атакующие страницы. Каждый сценарий — попытка
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
	"runtime"
	"strings"
	"sync/atomic"
	"time"
)

const (
	macFirefox = "/Applications/Firefox.app/Contents/MacOS/firefox"
)

// ID расширения и виджета его панели — из манифеста (как makeWidgetId в Firefox).
var extID, sidebarID string

func readExtID(extDir string) {
	raw, err := os.ReadFile(filepath.Join(extDir, "manifest.json"))
	must(err)
	var m struct {
		BSS struct {
			Gecko struct {
				ID string `json:"id"`
			} `json:"gecko"`
		} `json:"browser_specific_settings"`
	}
	must(json.Unmarshal(raw, &m))
	extID = m.BSS.Gecko.ID
	sidebarID = regexp.MustCompile(`[^a-z0-9_-]`).ReplaceAllString(strings.ToLower(extID), "_") + "-sidebar-action"
}

type env struct {
	m *Marionette
	p *Proxy
	// real: сценарии I* настоящей модели (флаг -real); model — модель для claude -p.
	real  bool
	model string
	// mcpConfig — конфигурация MCP для claude -p (только при -real).
	mcpConfig string
	// host — бинарник leash-host; home — домашний каталог стенда (сокет моста).
	host, home string
	// cur — идущая задача.
	cur *run
	// extraTab: адрес фоновой вкладки, которую task откроет после изоляции.
	extraTab string
}

// errSkip — сценарий не применим в этом режиме.
var errSkip = fmt.Errorf("пропущен")

func main() {
	only := flag.String("run", "", "запускать только сценарии, чьё имя содержит строку")
	headed := flag.Bool("headed", false, "показывать окно Firefox")
	real := flag.Bool("real", false, "настоящая модель через claude -p, сценарии из e2e/private")
	model := flag.String("model", "", "модель для -real (по умолчанию — модель Claude Code)")
	flag.Parse()

	root, err := filepath.Abs("..")
	must(err)
	extDir := filepath.Join(root, "extension")
	readExtID(extDir)
	if _, err := os.Stat(filepath.Join(extDir, "pkg", "leash_bg.wasm")); err != nil {
		fail("нет собранного WASM: сначала make build")
	}

	if *real {
		if _, err := exec.LookPath("claude"); err != nil {
			fail("для -real нужен Claude Code (claude) в PATH")
		}
	}
	host := filepath.Join(root, "target", "release", "leash-host")
	if _, err := os.Stat(host); err != nil {
		fail("нет собранного моста: сначала make host")
	}
	// Свой HOME: сокет и манифест моста не задевают настоящие. Путь короткий —
	// у адреса unix-сокета предел 104 байта.
	home, err := os.MkdirTemp("/tmp", "lh-e2e-")
	must(err)
	defer os.RemoveAll(home)
	install := exec.Command(host, "install")
	install.Env = append(os.Environ(), "HOME="+home)
	if out, err := install.CombinedOutput(); err != nil {
		fail("leash-host install: " + err.Error() + "\n" + string(out))
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
	ff := exec.Command(firefoxBin(), args...)
	ff.Env = append(os.Environ(), "HOME="+home)
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
	e := &env{m: m, p: p, real: *real, model: *model, host: host, home: home}
	if *real {
		e.mcpConfig, err = writeMCPConfig(host, home)
		must(err)
	}
	must(e.setup(extDir))
	defer e.finish()

	passed, failed, skipped := 0, 0, 0
	for _, s := range scenarios {
		if *only != "" && !strings.Contains(s.name, *only) {
			continue
		}
		start := time.Now()
		err := e.runScenario(s)
		if err == errSkip {
			skipped++
			continue
		}
		if err != nil {
			failed++
			fmt.Printf("FAIL %-44s %v\n", s.name, err)
		} else {
			passed++
			fmt.Printf("PASS %-44s (%.1fs)\n", s.name, time.Since(start).Seconds())
		}
	}
	fmt.Printf("\nИтог: %d прошло, %d упало, %d пропущено\n", passed, failed, skipped)
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
	// Firefox ищет манифест моста только в HOME стенда (на macOS он иначе
	// смотрит в настоящий ~/Library), до того как расширение подключится.
	if _, err := e.m.chrome(`const done = arguments[arguments.length - 1];
const { NativeManifests } = ChromeUtils.importESModule("resource://gre/modules/NativeManifests.sys.mjs");
NativeManifests.init().then(() => {
  NativeManifests._lookup = (type, name, context) => NativeManifests._tryPaths(type, name, [arguments[0]], context);
  done("ok");
}, e => done("ERR " + e));`, filepath.Dir(manifestDir(e.home))); err != nil {
		return fmt.Errorf("манифесты моста: %w", err)
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
mainWin().SidebarController
  .show(arguments[0]).then(() => done("ok"), e => done("ERR " + e));`, sidebarID); err != nil {
		return fmt.Errorf("панель: %w", err)
	}
	// Готово, когда мост поздоровался: панель показывает «подключён».
	deadline := time.Now().Add(20 * time.Second)
	for {
		var ready bool
		err := e.m.sidebar(`return w.document.getElementById("status").classList.contains("ok");`, &ready)
		if err == nil && ready {
			break
		}
		if time.Now().After(deadline) {
			var status string
			e.m.sidebar(`return w.document.getElementById("status").textContent;`, &status)
			return fmt.Errorf("мост не подключился: %q %v", status, err)
		}
		time.Sleep(300 * time.Millisecond)
	}
	var granted []string
	if err := e.m.sidebar(`
await w.browser.storage.local.set({allow_origins: "https://a.leash.test\nhttps://b.leash.test\nhttps://c.leash.test", deny_hosts: ""});
const all = await w.browser.permissions.getAll();
return Array.from(all.origins);`, &granted); err != nil {
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
	// I* — сценарии настоящей модели (-real); остальные — на сценарии драйвера.
	if strings.HasPrefix(s.name, "I") != e.real {
		return errSkip
	}
	lookupMiss.Store("")
	if err := s.run(e); err != nil {
		return err
	}
	if miss, _ := lookupMiss.Load().(string); miss != "" {
		return fmt.Errorf("стенд: в снимке нет элемента %q", miss)
	}
	return nil
}

// --- Сценарий «модели» ---

// step отвечает на n-й запрос сценария; видит запрос (и снимок в нём).
type step func(req APIRequest) Reply

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

// firefoxBin: $FIREFOX, иначе Firefox.app на macOS, иначе firefox из PATH.
func firefoxBin() string {
	if p := os.Getenv("FIREFOX"); p != "" {
		return p
	}
	if _, err := os.Stat(macFirefox); err == nil {
		return macFirefox
	}
	if p, err := exec.LookPath("firefox"); err == nil {
		return p
	}
	return macFirefox
}

// manifestDir — каталог манифестов native messaging Firefox в home (как
// paths::manifest_dir в leash-host).
func manifestDir(home string) string {
	if runtime.GOOS == "darwin" {
		return filepath.Join(home, "Library", "Application Support", "Mozilla", "NativeMessagingHosts")
	}
	return filepath.Join(home, ".mozilla", "native-messaging-hosts")
}
