package main

import (
	"fmt"
	"strings"
)

var (
	s          string   = ""
	arrayInput []string = []string{}
	r, y, g    int      = 0, 0, 0
)

func main() {
	for s == "" || len(arrayInput) != 5 {
		fmt.Scan(&s)
		arrayInput = strings.Split(s, "")
	}

	for _, v := range arrayInput {
		if v == "R" {
			r++
		}
		if v == "Y" {
			y++
		}
		if v == "G" {
			g++
		}
	}

	if r >= 3 || (r >= 2 && y >= 2) || r == 5 || y == 5 || r+y == 5 {
		fmt.Print("nakhor lite")
	} else {
		fmt.Print("rahat baash")
	}
}
