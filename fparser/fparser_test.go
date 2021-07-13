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
	assert.Contains(t, result[1][3], "AddAC11:FDRE")
}

func TestFileParser2(t *testing.T) {

}
