package main

import (
	"fmt"
	"math"
)

var (
	n   int = 0
	sum int = 0
)

func main() {
	for n < 1 || n > int(math.Pow(10, 18)) {
		fmt.Scan(&n)
	}

	for n != 0 {
		sum += n % 10
		n /= 10
		if n == 0 && sum/10 != 0 {
			n = sum
			sum = 0
		}
	}

	fmt.Print(sum)
}
