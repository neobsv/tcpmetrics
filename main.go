package main

import (
	"fmt"
	"log"
	"time"

	cs "github.com/thebsv/tcpmetrics/cscanner"
	fp "github.com/thebsv/tcpmetrics/fparser"
)

// Token is a data structure to hold the output of fparser.
type Token struct {
	tokens [][]string
}

// TokenQueue is a queue which stores a copy of the tokens parsed
// parsed by fparser, and keeps history over iterations of the control loop.
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
	return Token{tokens: make([][]string, 0)}, fmt.Errorf("queue is empty")
}

func (q *TokenQueue) length() int {
	return len(q.queue)
}

func controlLoop(qu TokenQueue) {

	tokens, err := fp.FileParser(1, "test1", 6, " ")
	if err != nil {
		log.Fatalf("could not parse the file")
	}

	cmap, err := cs.ConnectionScanner(tokens)
	if err != nil {
		log.Fatalf("could not obtain connnection map")
	}

	for conn := range cmap {
		log.Printf("New Connection: %s", conn)
	}

	qu.push(Token{
		tokens: tokens,
	})

	if qu.length() > 6 {
		qu.pop()
	}

	aggTokens := make([][]string, 0)

	for _, token := range qu.queue {
		aggTokens = append(aggTokens, token.tokens...)
	}

	pmap, err := cs.PortScanDetector(aggTokens)
	if err != nil {
		log.Fatalf("could not perform port scan detection")
	}

	if len(pmap) == 0 {
		log.Printf("No port scan detected")
		return
	}

	for ips, dstPorts := range pmap {
		log.Printf("Port scan detected: %s on ports %s", ips, dstPorts)
	}

}

func main() {

	qu := TokenQueue{queue: make([]Token, 0)}
	for {
		controlLoop(qu)
		time.Sleep(time.Second * 10)
	}
}
