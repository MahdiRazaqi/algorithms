package main

import (
	"fmt"
)

var (
	n int    = -1
	s string = ""
)

func main() {
	for 0 > n || n > 100 {
		fmt.Scan(&n)
	}
	for s == "" {
		fmt.Scan(&s)
	}
	for i := 0; i < n; i++ {
		fmt.Print("copy of ")
	}
	fmt.Print(s)
}
