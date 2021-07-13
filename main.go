package main

import (
	"log"

	cs "github.com/thebsv/tcpmetrics/cscanner"
	fp "github.com/thebsv/tcpmetrics/fparser"
)

func main() {
	log.Printf("main, input sanitization, control flow")
	tokens, err := fp.FileParser(1, "test1", 6, " ")
	if err != nil {
		log.Fatalf("could not parse the file")
	}

	cmap, err := cs.ConnectionScanner(tokens)
	if err != nil {
		log.Fatalf("could not obtain connnection map")
	}

	log.Printf("connection map: %v", cmap)

}
