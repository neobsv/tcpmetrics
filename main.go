package main

import (
	"log"
	"time"

	cs "github.com/thebsv/tcpmetrics/cscanner"
	fp "github.com/thebsv/tcpmetrics/fparser"
)

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

	// TODO: aggregate tokens from the queue before this function is called.
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
