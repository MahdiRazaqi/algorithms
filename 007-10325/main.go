package main

import (
	"fmt"
	"strconv"
)

var (
	r         int    = 0
	c         int    = 0
	direction string = "Right"
)

func main() {
	for 1 > r || r > 10 {
		fmt.Scan(&r)
	}
	for 1 > c || c > 20 {
		fmt.Scan(&c)
		if c > 10 {
			direction = "Left"
			c = 21 - c
		}
	}
	message := direction + " " + strconv.Itoa(11-r) + " " + strconv.Itoa(c)
	fmt.Print(message)
}
