package main

import (
	"flag"
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

func controlLoop(qu TokenQueue, filename string, conn_history map[string]bool) {
	// Setting the constants
	// 1 = number of lines from the top to be skipped
	// 6 = number of fields in a row
	// " " = the separator between each token in a row
	tokens, err := fp.FileParser(1, filename, 6, " ")
	if err != nil {
		log.Fatalf("could not parse the file")
	}

	cmap, err := cs.ConnectionScanner(tokens)
	if err != nil {
		log.Fatalf("could not obtain connnection map")
	}

	for conn := range cmap {
		// print connection only if it isnt in history
		if _, exist := conn_history[conn]; !exist {
			log.Printf("New Connection: %s", conn)
		}
	}

	// Add the connections from the current iteration to history
	for conn := range cmap {
		if _, exist := conn_history[conn]; !exist {
			conn_history[conn] = true
		}
	}

	qu.push(Token{
		tokens: tokens,
	})

	if qu.length() > 10 {
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

	var filename string
	flag.StringVar(&filename, "filename", "/proc/net/tcp", "The name of the file that needs to be parsed")
	flag.Parse()

	itn := 1
	// Queue object to store tokens after parsing, to maintain a running history
	// of connections, I'm limiting the queue length to 10, giving this a 100s time window
	// and connections are said to be unique in this time window
	qu := TokenQueue{queue: make([]Token, 0)}
	conn_history := make(map[string]bool)
	for i:=0; i < itn; i+=1 {
		log.Printf("============================== Iteration Number %d ==============================", itn)
		start := time.Now()
		controlLoop(qu, filename, conn_history)
		timediff := time.Since(start)

		if (i > 0) && ((i % 10) == 0) {
			// clear connection history
			for key := range conn_history {
				delete(conn_history, key)
			}
		}

		log.Printf("============================== Elapsed Time %v =============================", timediff)
		log.Printf("============================== End Iteration Number %d ==============================", i)
		time.Sleep(time.Second * 1)
	}

}
