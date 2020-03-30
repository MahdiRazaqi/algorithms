package main

import (
	"fmt"
	"strconv"
)

func main() {
	var lock int
	var password []int
	var temp int
	var orderLockNumber []int
	var totalCount int

	for lock < 1 || lock > 300000 {
		fmt.Scan(&lock)
	}

	for len(strconv.Itoa(temp)) != lock || temp == 0 {
		fmt.Scan(&temp)
	}
	for _, n := range strconv.Itoa(temp) {
		num, _ := strconv.Atoi(string(n))
		password = append(password, num)
	}

	for i := 1; i <= lock; i++ {
		fmt.Scan(&temp)
		orderLockNumber = append(orderLockNumber, temp)
	}

	for i := 0; i < lock; i++ {
		counter := 0
		for orderLockNumber[i] != 0 {
			counter++
			if orderLockNumber[i]%10 == password[i] {
				if counter > 5 {
					counter = 9 - counter
				}
				totalCount += counter
				break
			}
			orderLockNumber[i] /= 10
		}
	}

	fmt.Print(totalCount)
}
