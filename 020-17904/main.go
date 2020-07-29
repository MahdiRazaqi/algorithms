package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

var size int

func main() {
	fmt.Scan(&size)
	existArr := map[int]int{}

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 12800000), 12800000)

	scanner.Scan()
	list := strings.Split(scanner.Text(), " ")
	list = append(list, "")

	for day := 1; day <= (size/3)+1; day++ {
		flag := false
		test := 0
		matchIndex := []int{}
		for i := 1; i < len(list); i++ {
			if _, ok := existArr[i]; ok {
				continue
			}
			if list[test] != list[i] {
				if len(matchIndex) >= 2 {
					flag = true
					existArr[test] = day
					for _, val := range matchIndex {
						existArr[val] = day
					}
				}
				test = i
				matchIndex = []int{}
				continue
			}
			matchIndex = append(matchIndex, i)
		}
		if !flag {
			break
		}
	}

	var printQ []string
	for i := 0; i < len(list)-1; i++ {
		number := "-1"
		if v, ok := existArr[i]; ok {
			number = strconv.Itoa(int(v))
		}

		printQ = append(printQ, number)
	}

	printString := strings.Join(printQ, " ")
	fmt.Print(printString)
}
