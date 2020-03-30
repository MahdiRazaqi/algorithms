package main

import (
	"fmt"
)

var (
	pooyan  int
	badkhah int
	counter int
	temp    int = -1
)

func main() {
	for pooyan < 2 || pooyan > 100 || pooyan%2 != 0 {
		fmt.Scan(&pooyan)
	}

	for badkhah < 1 || badkhah > 1000 {
		fmt.Scan(&badkhah)
	}

	for 0 > temp || temp > pooyan/2 {
		counter++
		temp = (badkhah * counter) % pooyan
	}

	fmt.Print(badkhah * counter)
}
