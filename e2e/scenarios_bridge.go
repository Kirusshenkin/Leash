package main

// Мост: сеансы Claude приходят и уходят, Firefox остаётся.

import (
	"fmt"
	"strings"
	"time"
)

func init() {
	register(
		scenario{"B01 Сеанс Claude кончился при открытом вопросе: вопрос закрыт отказом, мост свободен", func(e *env) error {
			if err := e.task(A+"/forms", "отправь",
				reply(tool("read_page", nil)), clickByName("Далее-своя"), done("ок")); err != nil {
				return err
			}
			if _, err := e.waitConfirm(20 * time.Second); err != nil {
				return err
			}
			// Claude Code закрыт посреди вопроса.
			e.finish()
			closed := false
			for deadline := time.Now().Add(5 * time.Second); !closed && time.Now().Before(deadline); {
				found, _ := e.m.popup(`return null;`, nil)
				closed = !found
				time.Sleep(200 * time.Millisecond)
			}
			if !closed {
				return fmt.Errorf("вопрос умершего сеанса остался открыт")
			}
			// Следующий сеанс не ждёт таймаута чужого вопроса.
			start := time.Now()
			if err := e.task(A+"/", "прочитай", reply(tool("read_page", nil)), done("ок")); err != nil {
				return err
			}
			if _, err := e.waitIdle(10 * time.Second); err != nil {
				return err
			}
			reqs, posts, _ := e.p.snapshot()
			r, err := resultOf(reqs, 1)
			if err != nil {
				return err
			}
			if err := expect(!r.isError && strings.Contains(r.text, "Сайт A"), "второй сеанс не прочитал страницу: %s", truncate(r.text, 200)); err != nil {
				return err
			}
			if err := expect(len(posts) == 0, "форма отправлена: %v", posts); err != nil {
				return err
			}
			return expect(time.Since(start) < 8*time.Second, "второй сеанс ждал %v", time.Since(start))
		}},
	)
}
