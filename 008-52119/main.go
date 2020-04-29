package main

import (
	"fmt"
)

var (
	n int = 0
)

func main() {
	for 1 > n || n > 100 {
		fmt.Scan(&n)
	}
	for i := 0; i < n; i++ {
		fmt.Print("man khoshghlab hastam\n")
	}
}
