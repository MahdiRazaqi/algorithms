package main

import (
	"fmt"
)

var (
	n int = -300
)

func main() {
	for -273 >= n || n > 6000 {
		fmt.Scan(&n)
	}
	if n > 100 {
		fmt.Print("Steam")
	} else if n < 0 {
		fmt.Print("Ice")
	} else {
		fmt.Print("Water")
	}
}
