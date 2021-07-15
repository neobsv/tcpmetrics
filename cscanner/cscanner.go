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

// convertIPPort is a helper function for convertIPPortPair, which
// outputs the IPv4 address and port separately.
func convertIPPort(input string) (string, string, error) {
	temp := strings.Split(input, ":")
	ip, port := temp[0], temp[1]

	cip, err := convertIP(ip)
	if err != nil {
		log.Printf("the ip address could not be converted %s %v", input, err)
		return "", "", err
	}

	cport, err := convertPort(port)
	if err != nil {
		log.Printf("the port could not be converted %s %v", input, err)
		return "", "", err
	}

	return cip, cport, nil
}

// convertIPPortPair is a helper function which takes an IPv4:Port pair in hex,
// where the IPv4 is in little endian and port is in big endian. Outputs a human readable
// string in the regular [0-255].[0-255].[0-255].[0-255]:[0-65535] format.
func convertIPPortPair(input string) (string, error) {

	cip, cport, err := convertIPPort(input)
	if err != nil {
		log.Printf("the input could not be converted %s %v", input, err)
		return "", err
	}

	res := cip + ":" + cport

	return res, nil
}

// ConnectionScanner returns a map of tcp connections from the input tokens
// that have a unique(srcIP:srcPort, dstIP:dstPort).
func ConnectionScanner(tokens [][]string) (map[string]bool, error) {

	res := make(map[string]bool)

	for i := 0; i < len(tokens); i += 1 {
		local, err := convertIPPortPair(tokens[i][1])
		if err != nil {
			log.Panicf("IP hex to int conversion failed, exiting %v", err)
			return nil, err
		}
		remote, err := convertIPPortPair(tokens[i][2])
		if err != nil {
			log.Panicf("IP hex to int conversion failed, exiting %v", err)
			return nil, err
		}
		temp := local + " -> " + remote
		res[temp] = true
	}

	return res, nil
}

// PortScanDetector goes through the tokens input and records entries which have
// the same (srcIP, dstIP) tuples and varying dstPort s. Such entries are collected in
// a list and output.
func PortScanDetector(tokens [][]string) (map[string]string, error) {

	check_sport := make(map[string]map[string]bool)
	result := make(map[string]string)

	// Assuming
	check_srcip := map[string]bool{"10.0.2.15": true, "0.0.0.0": true, "127.0.0.1": true}

	for i := 0; i < len(tokens); i += 1 {
		srcIP, srcPort, err := convertIPPort(tokens[i][1])
		if err != nil {
			log.Panicf("IP hex to int conversion failed, exiting %v", err)
			return nil, err
		}
		dstIP, _, err := convertIPPort(tokens[i][2])
		if err != nil {
			log.Panicf("IP hex to int conversion failed, exiting %v", err)
			return nil, err
		}

		temp := srcIP + " -> " + dstIP

		// Look at the set of source ips which belong to set(0.0.0.0, 127.0.0.1, 10.0.2.15)
		if _, ok := check_srcip[srcIP]; ok {

			// Unique connections for CURRENT iteration
			if setOfSeenSrcPort, ok := check_sport[temp]; ok {

				// Unique source port was seen
				if _, exist := setOfSeenSrcPort[srcPort]; !exist {
					result[temp] += ", " + srcPort
					setOfSeenSrcPort[srcPort] = true
					check_sport[temp] = setOfSeenSrcPort
				}

				// If the src port for the connection exists in the set of seen source
				// ports, then we ignore it, since it is a duplicate.
			} else {

				// This is the first time a connection srcIP -> dstIP was seen
				result[temp] = srcPort

				// Create a new source port set and add the detected source port to it
				newSetSrcPort := make(map[string]bool)
				newSetSrcPort[srcPort] = true
				check_sport[temp] = newSetSrcPort
			}
			// End of unique connections for CURRENT iteration

		}

	}

	res := make(map[string]string)
	for ips, dstPorts := range result {
		if len(check_sport[ips]) >= 3 {
			res[ips] = dstPorts
		}
	}

	return res, nil
}
