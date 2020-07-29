package main

import (
	"fmt"
	"math"
)

var (
	n int = 0
)

func main() {
	for n < 1 || n > 1000000000 {
		fmt.Scan(&n)
	}
	pow := int(math.Log2(float64(n))) + 1
	fmt.Print(math.Pow(2, float64(pow)))
}
