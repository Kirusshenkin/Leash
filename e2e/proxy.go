package main

// HTTPS-прокси для профиля Firefox: на CONNECT отвечает сам, завершает TLS
// своим сертификатом (Firefox принимает его по acceptInsecureCerts) и
// обслуживает мок Anthropic API и тестовые сайты. Наружу не ходит ничего.

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// APIRequest — запрос расширения к мок API.
type APIRequest struct {
	Key  string
	Body map[string]any
	Raw  string
}

// Post — запрос на тестовый сайт не методом GET (отправка формы и т.п.).
type Post struct {
	Host, Path, Body string
}

// Reply — ответ мока: тело Messages API, задержка перед ним и HTTP-статус
// (0 — 200). Для ошибок API тело — {"type":"error","error":{...}}.
type Reply struct {
	Body   map[string]any
	Delay  time.Duration
	Status int
}

type Proxy struct {
	mu       sync.Mutex
	requests []APIRequest
	posts    []Post
	hits     []string
	script   func(n int, req APIRequest) Reply
	ln       net.Listener
	tls      *tls.Config
}

func newProxy() (*Proxy, error) {
	cert, err := selfSigned([]string{"api.anthropic.com", "a.leash.test", "b.leash.test", "c.leash.test", "www.tbank.ru"})
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &Proxy{ln: ln, tls: &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}}}
	go p.serve()
	return p, nil
}

func (p *Proxy) port() int { return p.ln.Addr().(*net.TCPAddr).Port }

func (p *Proxy) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handleConn(c)
	}
}

// handleConn: CONNECT host:443 → 200 → TLS → обычные HTTP-запросы.
func (p *Proxy) handleConn(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil || req.Method != http.MethodConnect {
		io.WriteString(c, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
		return
	}
	io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
	tc := tls.Server(c, p.tls)
	if err := tc.Handshake(); err != nil {
		return
	}
	tr := bufio.NewReader(tc)
	for {
		r, err := http.ReadRequest(tr)
		if err != nil {
			return
		}
		rw := newResponse()
		p.route(rw, r)
		if err := rw.writeTo(tc); err != nil {
			return
		}
	}
}

func (p *Proxy) route(w *response, r *http.Request) {
	host := strings.Split(r.Host, ":")[0]
	body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	p.mu.Lock()
	p.hits = append(p.hits, r.Method+" https://"+host+r.URL.RequestURI())
	p.mu.Unlock()
	if host == "api.anthropic.com" {
		p.api(w, r, body)
		return
	}
	if r.Method != http.MethodGet {
		p.mu.Lock()
		p.posts = append(p.posts, Post{Host: host, Path: r.URL.Path, Body: string(body)})
		p.mu.Unlock()
		w.header.Set("Content-Type", "text/html; charset=utf-8")
		w.body.WriteString("<!doctype html><title>ok</title><p>принято</p>")
		return
	}
	html, ok := sitePage(host, r.URL.Path)
	if !ok {
		w.status = 404
		return
	}
	// Страница вида "REDIRECT:<url>" — ответ 302 на этот адрес.
	if to, found := strings.CutPrefix(html, "REDIRECT:"); found {
		w.status = 302
		w.header.Set("Location", to)
		return
	}
	w.header.Set("Content-Type", "text/html; charset=utf-8")
	w.body.WriteString(html)
}

func (p *Proxy) api(w *response, r *http.Request, body []byte) {
	w.header.Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		w.header.Set("Access-Control-Allow-Methods", "POST")
		w.header.Set("Access-Control-Allow-Headers", "content-type, x-api-key, anthropic-version, anthropic-dangerous-direct-browser-access")
		w.status = 204
		return
	}
	var parsed map[string]any
	if r.Method != http.MethodPost || r.URL.Path != "/v1/messages" || json.Unmarshal(body, &parsed) != nil {
		w.status = 400
		return
	}
	req := APIRequest{Key: r.Header.Get("x-api-key"), Body: parsed, Raw: string(body)}
	p.mu.Lock()
	n := len(p.requests)
	p.requests = append(p.requests, req)
	script := p.script
	p.mu.Unlock()
	reply := Reply{Body: final("нет сценария")}
	if script != nil {
		reply = script(n, req)
	}
	time.Sleep(reply.Delay)
	if reply.Status != 0 {
		w.status = reply.Status
	}
	w.header.Set("Content-Type", "application/json")
	json.NewEncoder(&w.body).Encode(reply.Body)
}

// reset начинает сценарий: новый скрипт мока, пустые журналы.
func (p *Proxy) reset(script func(n int, req APIRequest) Reply) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.script = script
	p.requests = nil
	p.posts = nil
	p.hits = nil
}

func (p *Proxy) snapshot() ([]APIRequest, []Post, []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]APIRequest(nil), p.requests...), append([]Post(nil), p.posts...), append([]string(nil), p.hits...)
}

type response struct {
	status int
	header http.Header
	body   strings.Builder
}

func newResponse() *response { return &response{status: 200, header: http.Header{}} }

func (r *response) writeTo(w io.Writer) error {
	resp := http.Response{
		StatusCode:    r.status,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        r.header,
		Body:          io.NopCloser(strings.NewReader(r.body.String())),
		ContentLength: int64(r.body.Len()),
	}
	return resp.Write(w)
}

func selfSigned(hosts []string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "leash e2e"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     hosts,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// --- Ответы Messages API ---

type call struct {
	name  string
	input map[string]any
}

func tool(name string, input map[string]any) call {
	if input == nil {
		input = map[string]any{}
	}
	return call{name, input}
}

var toolSeq int

func tools(calls ...call) map[string]any {
	content := []any{}
	for _, c := range calls {
		toolSeq++
		content = append(content, map[string]any{
			"type": "tool_use", "id": "toolu_e2e_" + strconvItoa(toolSeq), "name": c.name, "input": c.input,
		})
	}
	return map[string]any{
		"type": "message", "role": "assistant", "content": content, "stop_reason": "tool_use",
		"usage": map[string]any{"input_tokens": 10, "output_tokens": 5},
	}
}

func final(text string) map[string]any {
	return map[string]any{
		"type": "message", "role": "assistant",
		"content":     []any{map[string]any{"type": "text", "text": text}},
		"stop_reason": "end_turn",
		"usage":       map[string]any{"input_tokens": 10, "output_tokens": 5},
	}
}

func strconvItoa(n int) string { return big.NewInt(int64(n)).String() }

// toolResults — результаты инструментов из последней реплики пользователя.
type result struct {
	text    string
	isError bool
}

func lastResults(req APIRequest) []result {
	msgs, _ := req.Body["messages"].([]any)
	if len(msgs) == 0 {
		return nil
	}
	last, _ := msgs[len(msgs)-1].(map[string]any)
	blocks, _ := last["content"].([]any)
	var out []result
	for _, b := range blocks {
		m, _ := b.(map[string]any)
		if m["type"] != "tool_result" {
			continue
		}
		text, _ := m["content"].(string)
		isErr, _ := m["is_error"].(bool)
		out = append(out, result{text, isErr})
	}
	return out
}

func systemPrompt(req APIRequest) string {
	s, _ := req.Body["system"].(string)
	return s
}
