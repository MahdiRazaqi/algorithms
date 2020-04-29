package main

import (
	"fmt"
)

var (
	n int = 0
)

func main() {
	for n < 1 || n > 100 {
		fmt.Scan(&n)
	}

	if n%2 == 0 {
		fmt.Print("Bala Barare")
	} else {
		fmt.Print("Payin Barare")
	}
}
