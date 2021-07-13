# tcpmetrics

## Problem Description

## Solution Design

## Implementation Details

## Testcase Specifications and Details

## Questions


## Improvements

- Added three spaces to the Trim function inside fparser.FileParser function while parsing rows, to avoid extra columns,
ideally this file should be parsed using a parsing library, by creating structs with the appropriate grammar.

- Convert IP function could be formalized to output better errors, and carry the IP and port in a struct, instead of
just using a string. Variable naming can be improved inside helper functions.
