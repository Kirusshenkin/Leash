package main

// HTTPS-прокси для профиля Firefox: на CONNECT отвечает сам, завершает TLS
// своим сертификатом (Firefox принимает его по acceptInsecureCerts) и
// обслуживает тестовые сайты. Наружу не ходит ничего: любой запрос на
// закрытый сайт виден в журнале как утечка.

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// APIRequest — шаг сценария глазами «модели»: результаты вызовов
// предыдущего шага (как их вернул мост) и что «модель» ответила на них.
type APIRequest struct {
	Results []result
	Resp    map[string]any
}

// Post — запрос на тестовый сайт не методом GET (отправка формы и т.п.).
type Post struct {
	Host, Path, Body string
}

// Reply — ход «модели»: вызовы инструментов (tools) или конец (final).
// Delay — пауза перед вызовами (страница успевает измениться после снимка).
type Reply struct {
	Body  map[string]any
	Delay time.Duration
}

type Proxy struct {
	mu       sync.Mutex
	requests []APIRequest
	posts    []Post
	hits     []string
	ln       net.Listener
	tls      *tls.Config
}

func newProxy() (*Proxy, error) {
	cert, err := selfSigned([]string{"a.leash.test", "b.leash.test", "c.leash.test", "www.tbank.ru"})
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

// reset начинает сценарий: пустые журналы.
func (p *Proxy) reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.requests = nil
	p.posts = nil
	p.hits = nil
}

// record добавляет шаг сценария.
func (p *Proxy) record(req APIRequest) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.requests = append(p.requests, req)
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

// --- Ходы «модели» ---

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

// tools — ход с вызовами инструментов (в форме ответа Messages API, чтобы
// сценарии читались как раньше).
func tools(calls ...call) map[string]any {
	content := []any{}
	for _, c := range calls {
		content = append(content, map[string]any{"type": "tool_use", "name": c.name, "input": c.input})
	}
	return map[string]any{"content": content, "stop_reason": "tool_use"}
}

func final(text string) map[string]any {
	return map[string]any{
		"content":     []any{map[string]any{"type": "text", "text": text}},
		"stop_reason": "end_turn",
	}
}

// callsOf — вызовы из хода «модели».
func callsOf(body map[string]any) []call {
	content, _ := body["content"].([]any)
	var out []call
	for _, b := range content {
		m, _ := b.(map[string]any)
		if m["type"] != "tool_use" {
			continue
		}
		name, _ := m["name"].(string)
		input, _ := m["input"].(map[string]any)
		out = append(out, tool(name, input))
	}
	return out
}

// result — ответ моста на один вызов.
type result struct {
	text    string
	isError bool
}

func lastResults(req APIRequest) []result { return req.Results }
