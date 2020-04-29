package main

import (
	"fmt"
)

var (
	x1 int = 0
	x2 int = 0
	y1 int = 0
	y2 int = 0
)

func main() {
	for x1 < 1 || x1 > 100 {
		fmt.Scan(&x1)
	}
	for y1 < 1 || y1 > 100 {
		fmt.Scan(&y1)
	}
	for x2 < 1 || x2 > 100 {
		fmt.Scan(&x2)
	}
	for y2 < 1 || y2 > 100 {
		fmt.Scan(&y2)
	}

	if x1 == x2 {
		fmt.Print("Vertical")
	} else if y1 == y2 {
		fmt.Print("Horizontal")
	} else {
		fmt.Print("Try again")
	}
}
