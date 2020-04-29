package main

import (
	"fmt"
)

var (
	a int = 0
	b int = 0
	l int = 0
	t int = 0
)

func main() {
	for a < 1 || a > 1000 {
		fmt.Scan(&a)
	}
	for b < 1 || b > 1000 {
		fmt.Scan(&b)
	}
	for l < 1 || l > 1000 {
		fmt.Scan(&l)
	}

	for i := 1; i <= l; i++ {
		if i%2 == 1 {
			t += a
		} else if i%2 == 0 {
			t += b
		}
	}

	fmt.Print(t)
}
