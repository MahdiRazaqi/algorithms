package main

import (
	"fmt"
	"strings"
)

var input string

func main() {
	fmt.Scan(&input)
	a := strings.Split(input, "")
	fmt.Print("saal:", a[0], a[1], "\n")
	fmt.Print("maah:", a[2], a[3], "\n")
}
