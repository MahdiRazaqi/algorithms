package main

import (
	"fmt"
)

var (
	row          int
	column       int
	numberOfBomb int
	bombRow      int
	bombColumn   int
)

func main() {
	fmt.Scan(&row)
	fmt.Scan(&column)
	fmt.Scan(&numberOfBomb)

	matrix := make([][]string, row)
	for i := 0; i < row; i++ {
		matrix[i] = make([]string, column)
	}

	for i := 1; i <= numberOfBomb; i++ {
		fmt.Scan(&bombRow)
		fmt.Scan(&bombColumn)
		matrix[bombRow-1][bombColumn-1] = "*"
	}

	for i := 0; i < row; i++ {
		for j := 0; j < column; j++ {
			if j != 0 {
				fmt.Print(" ")
			}
			if matrix[i][j] == "*" {
				fmt.Print(matrix[i][j])
			} else {
				fmt.Print(bombCounter(matrix, i, j))
			}
		}
		fmt.Print("\n")
	}
}

func bombCounter(arr [][]string, row, col int) (counter int) {
	for i := row - 1; i <= row+1; i++ {
		for j := col - 1; j <= col+1; j++ {
			if (i >= 0 && i < len(arr)) && (j >= 0 && j < len(arr[0])) && (arr[i][j] == "*") {
				counter++
			}
		}
	}
	return counter
}
