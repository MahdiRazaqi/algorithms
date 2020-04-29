package main

import (
	"fmt"
)

var (
	n       int   = 0
	numbers []int = []int{}
)

func main() {
	for count := 0; count < 1000; count++ {
		fmt.Scan(&n)
		if n == 0 {
			break
		}
		numbers = append(numbers, n)
	}

	for i := len(numbers); i > 0; i-- {
		fmt.Print(numbers[i-1], "\n")
	}
}
