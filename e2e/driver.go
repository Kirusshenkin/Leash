package main

// Драйвер в роли Claude: настоящий `leash-host mcp` (как его запускает
// Claude Code) и сценарий вызовов вместо модели. Каждая задача — новый
// MCP-процесс, то есть новый сеанс в расширении.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

type mcpClient struct {
	cmd *exec.Cmd
	in  io.WriteCloser
	out *bufio.Reader
	id  int
}

// startMCP запускает мост в режиме MCP с домашним каталогом стенда: сокет
// моста лежит в <home>/.leash.
func startMCP(host, home string) (*mcpClient, error) {
	cmd := exec.Command(host, "mcp")
	cmd.Env = append(os.Environ(), "HOME="+home)
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	c := &mcpClient{cmd: cmd, in: in, out: bufio.NewReaderSize(out, 1<<20)}
	if _, err := c.request("initialize", map[string]any{
		"protocolVersion": "2025-11-25",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "leash-e2e", "version": "0"},
	}); err != nil {
		c.close()
		return nil, fmt.Errorf("initialize: %w", err)
	}
	if err := c.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); err != nil {
		c.close()
		return nil, err
	}
	return c, nil
}

func (c *mcpClient) send(msg any) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	_, err = c.in.Write(append(b, '\n'))
	return err
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string { return fmt.Sprintf("%d %s", e.Code, e.Message) }

// request: запрос и ответ на него (stdio, JSON по строкам).
func (c *mcpClient) request(method string, params any) (json.RawMessage, error) {
	c.id++
	if err := c.send(map[string]any{"jsonrpc": "2.0", "id": c.id, "method": method, "params": params}); err != nil {
		return nil, err
	}
	for {
		line, err := c.out.ReadBytes('\n')
		if err != nil {
			return nil, fmt.Errorf("мост закрыл stdout: %w", err)
		}
		var resp struct {
			ID     *int            `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  *rpcError       `json:"error"`
		}
		if err := json.Unmarshal(line, &resp); err != nil {
			return nil, fmt.Errorf("не JSON от моста: %s", truncate(string(line), 200))
		}
		if resp.ID == nil || *resp.ID != c.id {
			continue
		}
		if resp.Error != nil {
			return nil, resp.Error
		}
		return resp.Result, nil
	}
}

// callTool: tools/call. Ошибка протокола (неизвестный инструмент, плохие
// аргументы) для «модели» выглядит как отказ, так и возвращается.
func (c *mcpClient) callTool(name string, args map[string]any) result {
	raw, err := c.request("tools/call", map[string]any{"name": name, "arguments": args})
	if err != nil {
		return result{text: "MCP: " + err.Error(), isError: true}
	}
	var res struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return result{text: "MCP: плохой результат " + string(raw), isError: true}
	}
	var text []string
	for _, b := range res.Content {
		if b.Type == "text" {
			text = append(text, b.Text)
		}
	}
	return result{text: strings.Join(text, "\n"), isError: res.IsError}
}

func (c *mcpClient) close() {
	c.in.Close()
	done := make(chan struct{})
	go func() { c.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		c.cmd.Process.Kill()
		<-done
	}
}

// --- Задача ---

// run — идущая задача: сценарий исполняется в своей горутине.
type run struct {
	done  chan struct{}
	final string
	err   error
	mcp   *mcpClient
}

// task: изоляция вкладок, Leash не на паузе, вкладка на url, затем сценарий
// вызовов через мост. text — задача пользователя, только для журнала.
func (e *env) task(url, text string, steps ...step) error {
	e.finish()
	// Изоляция сценариев: одна вкладка, она же активная (прошлые сценарии
	// могли открыть новые через window.open или target=_blank).
	if _, err := e.m.chrome(`const done = arguments[arguments.length - 1];
const g = mainWin().gBrowser;
for (const t of g.tabs.slice(1)) g.removeTab(t);
g.selectedTab = g.tabs[0];
done("ok");`); err != nil {
		return err
	}
	if e.extraTab != "" {
		if _, err := e.m.chrome(`const done = arguments[arguments.length - 1];
mainWin().gBrowser.addTab(arguments[0], {triggeringPrincipal: Services.scriptSecurityManager.getSystemPrincipal()});
done("ok");`, e.extraTab); err != nil {
			return err
		}
		e.extraTab = ""
		time.Sleep(1500 * time.Millisecond)
	}
	if err := e.resume(); err != nil {
		return err
	}
	e.p.reset()
	if url != "" {
		if err := e.m.navigate(url); err != nil {
			return fmt.Errorf("переход на %s: %w", url, err)
		}
	}
	mc, err := startMCP(e.host, e.home)
	if err != nil {
		return fmt.Errorf("мост: %w", err)
	}
	r := &run{done: make(chan struct{}), mcp: mc}
	e.cur = r
	go e.drive(r, steps)
	return nil
}

// drive: шаг сценария видит результаты предыдущего и решает, что вызвать.
// Ход без вызовов заканчивает задачу.
func (e *env) drive(r *run, steps []step) {
	defer close(r.done)
	var req APIRequest
	for n := 0; ; n++ {
		rep := Reply{Body: final("Готово.")}
		if n < len(steps) {
			rep = steps[n](req)
		}
		req.Resp = rep.Body
		e.p.record(req)
		calls := callsOf(rep.Body)
		if len(calls) == 0 {
			content, _ := rep.Body["content"].([]any)
			for _, b := range content {
				if m, _ := b.(map[string]any); m["type"] == "text" {
					r.final, _ = m["text"].(string)
				}
			}
			return
		}
		time.Sleep(rep.Delay)
		req = APIRequest{}
		for _, c := range calls {
			req.Results = append(req.Results, r.mcp.callTool(c.name, c.input))
		}
	}
}

// finish закрывает MCP-процесс прошлой задачи (сеанс в расширении кончается).
func (e *env) finish() {
	if e.cur == nil {
		return
	}
	e.cur.mcp.close()
	<-e.cur.done
	e.cur = nil
}

func (e *env) running() bool {
	if e.cur == nil {
		return false
	}
	select {
	case <-e.cur.done:
		return false
	default:
		return true
	}
}

// waitIdle ждёт конца сценария. Журнал — записи панели и последней
// строкой ответ «модели» (класс claude), как его увидел бы пользователь Claude.
func (e *env) waitIdle(timeout time.Duration) ([]logEntry, error) {
	if e.cur == nil {
		return e.log(), fmt.Errorf("задача не запущена")
	}
	select {
	case <-e.cur.done:
	case <-time.After(timeout):
		log := e.log()
		return log, fmt.Errorf("задача не закончилась за %v; журнал: %v", timeout, tail(log, 4))
	}
	log := append(e.log(), logEntry{Class: "claude", Text: e.cur.final})
	return log, e.cur.err
}

// --- Панель и окно подтверждения ---

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

// pendingConfirm: текст вопроса, если окно подтверждения открыто и его
// кнопки уже активны; иначе "".
func (e *env) pendingConfirm() string {
	var text *string
	found, _ := e.m.popup(`const a = w.document.getElementById("allow");
return a && !a.hasAttribute("disabled") ? w.document.getElementById("text").textContent : null;`, &text)
	if !found || text == nil {
		return ""
	}
	return *text
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

// answer нажимает кнопку в окне подтверждения, когда она станет активной.
func (e *env) answer(allow bool) error {
	if _, err := e.waitConfirm(10 * time.Second); err != nil {
		return err
	}
	id := "deny"
	if allow {
		id = "allow"
	}
	_, err := e.m.popup(fmt.Sprintf(`w.document.getElementById(%q).click(); return null;`, id), nil)
	return err
}

// stopLabel: текст кнопки «Стоп»/«Продолжить» в панели.
func (e *env) stopLabel() string {
	var s string
	e.m.sidebar(`return w.document.getElementById("stop").textContent;`, &s)
	return s
}

func (e *env) stop() error {
	if e.stopLabel() != "Стоп" {
		return nil
	}
	return e.m.sidebar(`w.document.getElementById("stop").click(); return null;`, nil)
}

// resume снимает паузу, оставленную прошлым сценарием.
func (e *env) resume() error {
	if e.stopLabel() != "Продолжить" {
		return nil
	}
	if err := e.m.sidebar(`w.document.getElementById("stop").click(); return null;`, nil); err != nil {
		return err
	}
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if e.stopLabel() == "Стоп" {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("Leash не снялся с паузы")
}
