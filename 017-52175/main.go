package main

import (
	"fmt"
	"strconv"
)

var (
	h int = -1
	m int = -1
)

func main() {
	for h < 0 || h > 11 {
		fmt.Scan(&h)
	}
	for m < 0 || m > 59 {
		fmt.Scan(&m)
	}

	h = 12 - h
	if h == 12 {
		h = 0
	}

	m = 60 - m
	if m == 60 {
		m = 0
	}

	hours := strconv.Itoa(h)
	if len(hours) == 1 {
		hours = "0" + hours
	}

	minutes := strconv.Itoa(m)
	if len(minutes) == 1 {
		minutes = "0" + minutes
	}

	fmt.Print(hours, ":", minutes)
}
