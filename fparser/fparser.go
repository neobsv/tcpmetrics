package fparser

import (
	"bufio"
	"io"
	"log"
	"os"
	"strings"
)

// safeOpen is a function used to safely open a file for reading, this is to remain
// safe while parsing special files, like those under /proc.
func safeOpen(filen string) (*os.File, error) {
	fptr, err := os.Open(filen)
	if err != nil {
		log.Fatalf("Unable to open file %s for reading, due to error %v", filen, err)
		return nil, err
	}
	return fptr, nil
}

// FileParser reads a specified input file, skipping n lines from the top of the file
// specified by head. The nCols argument is used to split each row into the number of
// columns specified to tokenize the row, and the separator is the string between two
// values in each row. The return value is a 2D string array, which contains the tokenized
// contents of the entire file.
func FileParser(head int, fileName string, nFields int, separator string) ([][]string, error) {

	var inputFile io.Reader
	if fileName != "" {
		fptr, err := safeOpen(fileName)
		if err != nil {
			return nil, err
		}
		defer fptr.Close()
		inputFile = fptr
	}

	// Skip n lines from the top of the file, to remove headings
	buffer := bufio.NewScanner(inputFile)
	for i := 0; i < head; i += 1 {
		if !buffer.Scan() {
			return nil, buffer.Err()
		}
		log.Printf("> skipping line : %s \n", buffer.Text())
	}

	// tokenize the file, row by row into a 2D array of strings
	var parsed [][]string
	for {
		if !buffer.Scan() {
			if buffer.Err() != nil {
				return nil, buffer.Err()
			} else {
				break
			}
		}
		temp := strings.Trim(buffer.Text(), "\r\n\t   ")
		parsed = append(parsed, strings.SplitN(temp, separator, nFields))
	}

	return parsed, nil
}
