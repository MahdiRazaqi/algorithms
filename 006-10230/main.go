package main

import "fmt"

var (
	d1 int = -1
	d2 int = -1
	d3 int = -1
)

func main() {
	for 0 > d1 || d1 > 360 {
		fmt.Scan(&d1)
	}
	for 0 > d2 || d2 > 360 {
		fmt.Scan(&d2)
	}
	for 0 > d3 || d3 > 360 {
		fmt.Scan(&d3)
	}

	if d1 == 0 || d2 == 0 || d3 == 0 {
		fmt.Print("No")
	} else {
		if total := d1 + d2 + d3; total == 180 {
			fmt.Print("Yes")
		} else {
			fmt.Print("No")
		}
	}
}
