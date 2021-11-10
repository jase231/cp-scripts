package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func main() {
	setFirewallRules()
}
func setFirewallRules() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("List any ports that need to remain open in format 22,443, etc: ")
	input, _ := reader.ReadString('\n')
	inputsplice := strings.Split(input, ",")
	for index, curinput := range inputsplice {
		if 
	}
	ports := [12]string{"22", "21", "23", "25", "80", "161", "162", "8080", "3389", "4444", "8088", "8888"}
	for index, element := range ports {

	}
}
