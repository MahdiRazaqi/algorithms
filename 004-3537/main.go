package main

import "fmt"

var (
	number int    = 0
	wow    string = "W"
)

func main() {
	for 1 > number || number > 10 {
		fmt.Scan(&number)
	}
	for number >= 1 {
		wow += "o"
		number--
	}
	wow += "w!"
	fmt.Print(wow)
}
