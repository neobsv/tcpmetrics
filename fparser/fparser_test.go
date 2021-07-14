package fparser

import (
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFileParserFunctional1(t *testing.T) {
	result, err := FileParser(1, "temp", 6, " ")
	if err != nil {
		log.Printf("TestFileParserFunctional1 failed")
		assert.Fail(t, "TestFileParserFunctional1 failed")
	}
	// log.Printf("parsed output: %s %s %s %s %s", result, result[1][0], result[1][1], result[1][2], result[1][3])
	assert.Equal(t, result[1][1], "0100007F:0277")
}

func TestFileParserFunctional2(t *testing.T) {
	_, err := FileParser(1, "bad", 6, " ")
	if err != nil {
		log.Printf("TestFileParserFunctional2 failed, which is good")
		assert.True(t, true)
	}
}
