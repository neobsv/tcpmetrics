package cscanner

import (
	"fmt"
	"log"
	"strconv"
	"strings"
)

// revs is a helper to reverse a string
func revs(s string) string {
	i := len(s)
	res := make([]rune, i)
	for _, x := range s {
		i--
		res[i] = x
	}
	return string(res)
}

// convertPort is a helper function for the convertIPPortPair function
func convertPort(port string) (string, error) {
	res, err := strconv.ParseInt(port, 16, 64)
	if err != nil {
		log.Printf("Could not parse port %s", port)
		return "", err
	}
	return fmt.Sprintf("%d", res), nil
}

// convertIP is a helper function for the convertIPPortPair function
func convertIP(ip string) (string, error) {
	res := make([]string, 4)
	idx := 0
	wip := revs(ip)

	for i1 := 0; i1 < 8; i1 += 2 {
		nibble, err := strconv.ParseInt(revs(wip[i1:i1+2]), 16, 32)
		res[idx] = fmt.Sprintf("%d", nibble)
		if err != nil {
			log.Printf("Could not parse nibble %s", wip[i1:i1+2])
			return "", err
		}
		idx += 1
	}

	cip := strings.Join(res, ".")
	return cip, nil
}

// convertIPPortPair is a helper function which takes an IPv4:Port pair in hex,
// where the IPv4 is in little endian and port is in big endian. Outputs a human readable
// string in the regular [0-255].[0-255].[0-255].[0-255]:[0-65535] format.
func convertIPPortPair(input string) (string, error) {
	temp := strings.Split(input, ":")
	ip, port := temp[0], temp[1]

	cip, err := convertIP(ip)
	if err != nil {
		log.Printf("the ip address could not be converted %s %v", input, err)
		return "", err
	}

	cport, err := convertPort(port)
	if err != nil {
		log.Printf("the ip address could not be converted %s %v", input, err)
		return "", err
	}

	res := cip + ":" + cport

	return res, nil
}

// ConnectionScanner returns a map of tcp connections from the input tokens
// that have a unique(srcIP:srcPort, dstIP:dstPort).
func ConnectionScanner(tokens [][]string) (map[string]bool, error) {
	log.Printf("logic to count / filter tokens after parsing")
	return nil, nil
}
