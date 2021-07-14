package main

import "fmt"

type Token struct {
	tokens [][]string
}

type TokenQueue struct {
	queue []Token
}

func (q *TokenQueue) push(t Token) {
	q.queue = append(q.queue, t)
}

func (q *TokenQueue) pop() (Token, error) {
	if len(q.queue) > 0 {
		ret := q.queue[0]
		q.queue = q.queue[1:]
		return ret, nil
	}
	return Token{tokens: make([][]string, 0)}, fmt.Errorf("Queue is empty")
}

func (q *TokenQueue) top() (Token, error) {
	if len(q.queue) > 0 {
		return q.queue[0], nil
	}
	return Token{tokens: make([][]string, 0)}, fmt.Errorf("Queue is empty")
}

func (q *TokenQueue) length() int {
	return len(q.queue)
}
