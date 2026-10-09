package main

// Клиент Marionette (TCP, кадры "длина:json") и действия с браузером.
// Панель расширения живёт в удалённом <browser>, куда Marionette переключиться
// не может, поэтому скрипты в панели исполняются frame script'ом через
// message manager: content там — окно панели.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

type Marionette struct {
	conn net.Conn
	r    *bufio.Reader
	id   int
	ctx  string
	tag  int
}

func dialMarionette(port int, wait time.Duration) (*Marionette, error) {
	deadline := time.Now().Add(wait)
	for {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			m := &Marionette{conn: c, r: bufio.NewReader(c)}
			if _, err := m.read(); err != nil {
				return nil, err
			}
			return m, nil
		}
		if time.Now().After(deadline) {
			return nil, err
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func (m *Marionette) read() ([]byte, error) {
	lenStr, err := m.r.ReadString(':')
	if err != nil {
		return nil, err
	}
	n, err := strconv.Atoi(strings.TrimSuffix(lenStr, ":"))
	if err != nil {
		return nil, err
	}
	buf := make([]byte, n)
	_, err = io.ReadFull(m.r, buf)
	return buf, err
}

func (m *Marionette) call(name string, params any) (json.RawMessage, error) {
	m.id++
	b, err := json.Marshal([]any{0, m.id, name, params})
	if err != nil {
		return nil, err
	}
	m.conn.SetDeadline(time.Now().Add(90 * time.Second))
	if _, err := fmt.Fprintf(m.conn, "%d:%s", len(b), b); err != nil {
		return nil, err
	}
	for {
		raw, err := m.read()
		if err != nil {
			return nil, err
		}
		var resp []json.RawMessage
		if err := json.Unmarshal(raw, &resp); err != nil || len(resp) != 4 {
			return nil, fmt.Errorf("%s: плохой ответ %s", name, raw)
		}
		var id int
		json.Unmarshal(resp[1], &id)
		if id != m.id {
			continue
		}
		if string(resp[2]) != "null" {
			return nil, fmt.Errorf("%s: %s", name, truncate(string(resp[2]), 400))
		}
		var wrapped struct {
			Value json.RawMessage `json:"value"`
		}
		if json.Unmarshal(resp[3], &wrapped) == nil && wrapped.Value != nil {
			return wrapped.Value, nil
		}
		return resp[3], nil
	}
}

func (m *Marionette) context(ctx string) error {
	if m.ctx == ctx {
		return nil
	}
	_, err := m.call("Marionette:SetContext", map[string]any{"value": ctx})
	if err == nil {
		m.ctx = ctx
	}
	return err
}

// mainWinJS: главное окно браузера, а не окно подтверждения Leash (у того
// скрыта панель инструментов). Доступна в каждом chrome-скрипте как mainWin().
const mainWinJS = `const mainWin = () => {
  for (const w of Services.wm.getEnumerator("navigator:browser")) {
    if (!(w.document.documentElement.getAttribute("chromehidden") || "").includes("toolbar")) return w;
  }
  return Services.wm.getMostRecentWindow("navigator:browser");
};
`

// chrome исполняет асинхронный скрипт с привилегиями браузера.
// Последний аргумент скрипта — функция завершения.
func (m *Marionette) chrome(script string, args ...any) (json.RawMessage, error) {
	if err := m.context("chrome"); err != nil {
		return nil, err
	}
	if args == nil {
		args = []any{}
	}
	return m.call("WebDriver:ExecuteAsyncScript", map[string]any{"script": mainWinJS + script, "args": args})
}

// frameRun: исполнить code в странице браузера inner (frame-скрипт) и вернуть
// результат. Общая часть для панели и окна подтверждения.
const frameRun = `
const mm = inner.messageManager;
mm.addMessageListener(tag, function l(msg) { mm.removeMessageListener(tag, l); done(msg.data); });
const fs = "Promise.resolve().then(() => (async function (w) {" + code + "})(content.wrappedJSObject))" +
  ".then(v => sendAsyncMessage(" + JSON.stringify(tag) + ", {ok: JSON.stringify(v === undefined ? null : v)}))" +
  ".catch(e => sendAsyncMessage(" + JSON.stringify(tag) + ", {err: String(e)}))";
mm.loadFrameScript("data:application/javascript;charset=utf-8," + encodeURIComponent(fs), false);
`

const sidebarScript = `
const [code, tag] = arguments;
const done = arguments[arguments.length - 1];
const win = mainWin();
const outer = win.SidebarController.browser;
const inner = outer.contentDocument && outer.contentDocument.getElementById("webext-panels-browser");
if (!inner || !inner.messageManager) { done({err: "панель не открыта"}); return; }
` + frameRun

// popupScript: то же для окна подтверждения Leash; нет окна — {none: true}.
// Если окон несколько (прошлое ещё закрывается), берётся самый новый вопрос.
const popupScript = `
const [code, tag] = arguments;
const done = arguments[arguments.length - 1];
let inner = null, best = -1;
for (const w of Services.wm.getEnumerator("navigator:browser")) {
  const b = w.gBrowser && w.gBrowser.selectedBrowser;
  const m = b && b.currentURI.spec.match(/\/confirm\/confirm\.html#(\d+)$/);
  if (m && b.messageManager && Number(m[1]) > best) { best = Number(m[1]); inner = b; }
}
if (!inner) { done({none: true}); return; }
` + frameRun

// popup — как sidebar, но в окне подтверждения. found=false: окна нет.
func (m *Marionette) popup(code string, out any) (found bool, err error) {
	m.tag++
	raw, err := m.chrome(popupScript, code, fmt.Sprintf("leash-e2e-%d", m.tag))
	if err != nil {
		return false, err
	}
	var res struct {
		Ok   *string `json:"ok"`
		Err  *string `json:"err"`
		None bool    `json:"none"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return false, fmt.Errorf("окно подтверждения: %s", raw)
	}
	if res.None {
		return false, nil
	}
	if res.Err != nil {
		return true, fmt.Errorf("окно подтверждения: %s", *res.Err)
	}
	if out != nil && res.Ok != nil {
		return true, json.Unmarshal([]byte(*res.Ok), out)
	}
	return true, nil
}

// sidebar исполняет тело async-функции с аргументом w — окном панели
// (window, видимый ей самой) и возвращает результат через JSON.
func (m *Marionette) sidebar(code string, out any) error {
	m.tag++
	raw, err := m.chrome(sidebarScript, code, fmt.Sprintf("leash-e2e-%d", m.tag))
	if err != nil {
		return err
	}
	var res struct {
		Ok  *string `json:"ok"`
		Err *string `json:"err"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return fmt.Errorf("панель: %s", raw)
	}
	if res.Err != nil {
		return fmt.Errorf("панель: %s", *res.Err)
	}
	if out == nil || res.Ok == nil {
		return nil
	}
	return json.Unmarshal([]byte(*res.Ok), out)
}

func (m *Marionette) navigate(url string) error {
	if err := m.context("content"); err != nil {
		return err
	}
	_, err := m.call("WebDriver:Navigate", map[string]any{"url": url})
	return err
}

func (m *Marionette) currentURL() string {
	if err := m.context("content"); err != nil {
		return ""
	}
	raw, err := m.call("WebDriver:GetCurrentURL", map[string]any{})
	if err != nil {
		return ""
	}
	var s string
	json.Unmarshal(raw, &s)
	return s
}

// page исполняет синхронный скрипт в странице текущей вкладки.
func (m *Marionette) page(script string) (json.RawMessage, error) {
	if err := m.context("content"); err != nil {
		return nil, err
	}
	return m.call("WebDriver:ExecuteScript", map[string]any{"script": script, "args": []any{}})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
