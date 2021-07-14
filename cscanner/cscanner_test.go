package cscanner

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConnectionScanner1(t *testing.T) {
	perms := [][]string{
		{"0:", "3500007F:0035", "00000000:0000", "0A 00000000:00000000 00:00000000 00000000   101        0 20540 1 0000000000000000 100 0 0 10 0"},
		{"17:", "0F02000A:96DE", "339E2E34:01BB", "01 00000000:00000000 02:000002FC 00000000  1000        0 46689 2 0000000000000000 26 4 24 10 -1"},
		{"18:", "0F02000A:E97E", "59B871D8:01BB", "01 00000000:00000000 02:00000055 00000000  1000        0 43659 2 0000000000000000 24 4 26 10 -1"},
		{"19:", "0F02000A:9DA4", "6221FB8E:01BB", "01 00000000:00000000 00:00000000 00000000  1000        0 46059 1 0000000000000000 21 4 13 10 -1"},
		{"20:", "0F02000A:E58E", "8594FE68:01BB", "01 00000000:00000000 02:000001FF 00000000  1000        0 46155 2 0000000000000000 24 4 30 10 -1"},
		{"21:", "0F02000A:D686", "CE45FA8E:01BB", "01 00000000:00000000 00:00000000 00000000  1000        0 40952 1 0000000000000000 21 4 0 10 -1"},
		{"22:", "0F02000A:E2BC", "6DD9FA8E:01BB", "01 00000000:00000000 00:00000000 00000000  1000        0 45308 1 0000000000000000 21 4 1 10 -1"},
	}
	answers := map[string]bool{"10.0.2.15:38622 -> 52.46.158.51:443": true, "10.0.2.15:40356 -> 142.251.33.98:443": true, "10.0.2.15:54918 -> 142.250.69.206:443": true, "10.0.2.15:58044 -> 142.250.217.109:443": true, "10.0.2.15:58766 -> 104.254.148.133:443": true, "10.0.2.15:59774 -> 216.113.184.89:443": true, "127.0.0.53:53 -> 0.0.0.0:0": true}

	map_connections, err := ConnectionScanner(perms)
	if err != nil {
		assert.Fail(t, "The listed tokens could not be parsed correctly.")
	}

	//log.Printf("map of connections: %v", map_connections)
	assert.Equal(t, map_connections, answers)
}

func TestPortScanDetector1(t *testing.T) {
	perms := [][]string{
		{"0:", "3500007F:0000", "339E2E34:0035", "0A 00000000:00000000 00:00000000 00000000   101        0 20540 1 0000000000000000 100 0 0 10 0"},
		{"17:", "3500007F:A099", "339E2E34:01BB", "01 00000000:00000000 02:000002FC 00000000  1000        0 46689 2 0000000000000000 26 4 24 10 -1"},
		{"18:", "0F02000A:E97E", "59B871D8:01BB", "01 00000000:00000000 02:00000055 00000000  1000        0 43659 2 0000000000000000 24 4 26 10 -1"},
		{"19:", "0F02000A:02FC", "6221FB8E:01FB", "01 00000000:00000000 00:00000000 00000000  1000        0 46059 1 0000000000000000 21 4 13 10 -1"},
		{"20:", "0F02000A:E2BC", "6221FB8E:0035", "01 00000000:00000000 02:000001FF 00000000  1000        0 46155 2 0000000000000000 24 4 30 10 -1"},
		{"21:", "0F02000A:014A", "6221FB8E:01BA", "01 00000000:00000000 00:00000000 00000000  1000        0 40952 1 0000000000000000 21 4 0 10 -1"},
		{"22:", "0F02000A:E2BC", "6DD9FA8E:01BB", "01 00000000:00000000 00:00000000 00000000  1000        0 45308 1 0000000000000000 21 4 1 10 -1"},
	}
	answers := map[string]string{"10.0.2.15 -> 142.251.33.98": "507, 53, 442"}

	port_scans, err := PortScanDetector(perms)
	if err != nil {
		assert.Fail(t, "Port scan detection could not be performed on the tokens")
	}

	// assert.Fail(t, "test %v", port_scans)

	for ips, expected_ports := range answers {
		if actual_ports, ok := port_scans[ips]; ok {
			actualps := strings.Split(actual_ports, ", ")
			expectedps := strings.Split(expected_ports, ", ")
			assert.ElementsMatch(t, expectedps, actualps)
		} else {
			assert.Fail(t, "An expected result %s %s was not obtained", ips, expected_ports)
		}
	}

}
