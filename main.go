package main

import (
	"log"

	cs "github.com/thebsv/tcpmetrics/cscanner"
	fp "github.com/thebsv/tcpmetrics/fparser"
)

func main() {

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

	pmap, err := cs.PortScanDetector(tokens)
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
