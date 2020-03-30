package main

import "fmt"

var (
	number int = 0
	fact   int = 1
)

func main() {
	for 1 > number || number > 10 {
		fmt.Scan(&number)
	}
	for number >= 1 {
		fact *= number
		number--
	}
	fmt.Print(fact)
}
