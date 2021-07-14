# tcpmetrics

## Problem Description

## Solution Design

## Implementation Details

## Testcase Specifications and Details

## Questions


## Improvements

-  Ideally this file should be parsed using a parsing library, by creating structs with the appropriate grammar.

- Convert IP function could be formalized to output better errors, and carry the IP and port in a struct, instead of
just using a string. Variable naming can be improved inside helper functions.

- Numbers in the convertIP and convertPort function could be written as constants

## To clarify

- Define port scan, is it detection of similar tuple(srcIP, dstIP) with varying dstPort or are we looking for some patterns
that the dstPorts exhibit