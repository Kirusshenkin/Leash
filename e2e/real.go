package main

// Настоящая модель (-real): Claude Code в режиме `claude -p` с мостом стенда.
// Из инструментов у него только MCP-сервер Leash: встроенные (Bash, WebFetch
// и прочие) выключены, пользовательские настройки и хуки не грузятся, сеанс
// не сохраняется. Авторизация — обычная авторизация Claude Code пользователя;
// HOME стенда получает только MCP-сервер.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// writeMCPConfig: конфигурация MCP для claude -p — наш leash-host с HOME стенда.
func writeMCPConfig(host, home string) (string, error) {
	cfg := map[string]any{"mcpServers": map[string]any{
		"leash": map[string]any{"command": host, "args": []string{"mcp"}, "env": map[string]string{"HOME": home}},
	}}
	b, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	path := filepath.Join(home, "mcp.json")
	return path, os.WriteFile(path, b, 0o600)
}

// realTask: вкладка на url, затем задача пользователя настоящему Claude.
// Каждое сообщение модели пишется в журнал шагов (APIRequest.Resp), чтобы
// после прогона было видно, что она пыталась вызвать.
func (e *env) realTask(url, text string) error {
	if err := e.prepare(url); err != nil {
		return err
	}
	work := filepath.Join(e.home, "work")
	if err := os.MkdirAll(work, 0o700); err != nil {
		return err
	}
	args := []string{"-p", text,
		"--mcp-config", e.mcpConfig, "--strict-mcp-config",
		"--tools", "", "--allowedTools", "mcp__leash",
		"--setting-sources", "project", "--no-session-persistence",
		"--output-format", "stream-json", "--verbose"}
	if e.model != "" {
		args = append(args, "--model", e.model)
	}
	cmd := exec.Command("claude", args...)
	cmd.Dir = work
	for _, kv := range os.Environ() {
		// Не выдавать прогон за вложенный сеанс Claude Code, если стенд запущен из него.
		if !strings.HasPrefix(kv, "CLAUDECODE=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("claude: %w", err)
	}
	r := &run{done: make(chan struct{}), claude: cmd}
	e.cur = r
	go func() {
		defer close(r.done)
		sc := bufio.NewScanner(out)
		sc.Buffer(make([]byte, 1<<20), 16<<20)
		for sc.Scan() {
			var ev struct {
				Type    string         `json:"type"`
				Message map[string]any `json:"message"`
				Result  string         `json:"result"`
				IsError bool           `json:"is_error"`
			}
			if json.Unmarshal(sc.Bytes(), &ev) != nil {
				continue
			}
			switch ev.Type {
			case "assistant":
				e.p.record(APIRequest{Resp: ev.Message})
			case "result":
				r.final = ev.Result
				if ev.IsError {
					r.err = fmt.Errorf("claude: %s", truncate(ev.Result, 300))
				}
			}
		}
		if err := cmd.Wait(); err != nil && r.err == nil {
			r.err = fmt.Errorf("claude: %v: %s", err, truncate(stderr.String(), 300))
		}
	}()
	return nil
}
