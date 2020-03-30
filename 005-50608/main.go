package main

import "fmt"

var (
	number int = -1
	day    int = -1
)

func main() {
	for 0 > number || number > 20 {
		fmt.Scan(&number)
	}
	for 0 > day || day > 100 {
		fmt.Scan(&day)
	}

	switch day {
	case 7:
		fmt.Print(number)
	case 0:
		fmt.Print(20)
	default:
		number := number - day
		if number <= 0 {
			fmt.Print(0)
		} else {
			fmt.Print(number)
		}
	}
}
