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

	log.Printf("logic to count / filter tokens after parsing")
	return res, nil
}

// PortScanDetector goes through the tokens input and records entries which have
// the same (srcIP, dstIP) tuples and varying dstPort s. Such entries are collected in
// a list and output.
func PortScanDetector(tokens [][]string) ([]string, error) {

	check := make(map[string]bool)
	check_dport := make(map[string]bool)
	result := make(map[string]string)

	for i := 0; i < len(tokens); i += 1 {
		srcIP, _, err := convertIPPort(tokens[i][1])
		if err != nil {
			log.Panicf("IP hex to int conversion failed, exiting %v", err)
			return nil, err
		}
		dstIP, dstPort, err := convertIPPort(tokens[i][2])
		if err != nil {
			log.Panicf("IP hex to int conversion failed, exiting %v", err)
			return nil, err
		}
		temp := srcIP + " -> " + dstIP
		if _, ok := check[temp]; ok {
			if _, ok := check_dport[dstPort]; !ok {
				result[temp] += ", " + dstPort
			} else {
				check_dport[dstPort] = true
			}
		} else {
			check[temp] = true
			result[temp] = dstPort
		}
	}

	res := make([]string, 0)
	for ips, dstPorts := range result {
		if strings.Contains(dstPorts, ",") {
			res = append(res, fmt.Sprintf("Port Scan detected: %s on ports %s", ips, dstPorts))
		}
	}

	return res, nil
}
