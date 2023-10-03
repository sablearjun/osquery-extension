package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

var (
	// Osqueryd
	socket = flag.String("socket", "/var/osquery/osquery.em", "Path to osquery socket file")

	// Osqueryd
	// socket = flag.String("socket", "/root/.osquery/shell.em", "Path to osquery socket file")
)

func main() {

	flag.Int("timeout", 0, "")
	flag.Int("interval", 0, "")
	flag.Bool("verbose", false, "")
	// Check if the program is run with root privileges
	if os.Geteuid() != 0 {
		fmt.Println("This program must be run as root.")
		return
	}

	flag.Parse()

	// Osquery socket path
	if *socket == "" {
		log.Fatal("Missing socket path")
	}

	// Create a new extension manager
	manager, err := osquery.NewExtensionManagerServer("vajra_linux_extension", *socket)
	if err != nil {
		log.Fatalf("Failed to create extension manager: %v", err)
	}

	// Register the port_block table
	manager.RegisterPlugin(table.NewPlugin("port_block", PortBlockColumns(), PortBlockGenerate))

	// Start the extension manager
	err = manager.Run()
	if err != nil {
		log.Fatalf("Failed to start extension manager: %v", err)
	}

	// Wait for termination signal
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	<-signalChan

	// Clean up resources
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	manager.Shutdown(ctx)
}

// PortBlockColumns defines the columns of the port_block table
func PortBlockColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("port"),
		table.TextColumn("action"),
		table.TextColumn("reason"),
		table.TextColumn("message"),
	}
}

func blockPort(port string) {
	if isUFWInstalled() {
		blockWithUFW(port)
	} else {
		blockWithIPTables(port)
	}
}

func allowPort(port string) {
	if isUFWInstalled() {
		allowWithUFW(port)
	} else {
		allowWithIPTables(port)
	}
}

func blockWithUFW(port string) {
	// Enable ufw if it's not already enabled
	if !isUFWEnabled() {
		if !enableUFW() {
			fmt.Println("Failed to enable UFW. Exiting.")
			return
		}
		fmt.Println("UFW has been enabled.")
	}

	// Run the ufw command to block the specified port
	print(port)
	blockCommand := exec.Command("sudo", "ufw", "deny", "in", port+"/tcp")
	blockOutCommand := exec.Command("sudo", "ufw", "deny", "out", port+"/tcp")
	blockOutput, err := blockCommand.CombinedOutput()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	blockOutOutput, err := blockOutCommand.CombinedOutput()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println("Out command:", blockOutOutput)

	fmt.Println("Command Output:", string(blockOutput))
}

func allowWithUFW(port string) {
	// Run the ufw command to allow the specified port
	allowInCommand := exec.Command("ufw", "delete", "deny", "in", port+"/tcp")
	allowOutCommand := exec.Command("ufw", "delete", "deny", "out", port+"/tcp")
	allowOutput, err := allowInCommand.CombinedOutput()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	allowOutOutput, err := allowOutCommand.CombinedOutput()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	print(allowOutOutput)
	fmt.Println("Command Output:", string(allowOutput))
}

func blockWithIPTables(port string) {
	iptablesInCommand := exec.Command("sudo", "iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", port, "-j", "DROP", "-m", "comment", "--comment", "Vajra Rule")
	iptablesOutCommand := exec.Command("sudo", "iptables", "-I", "OUTPUT", "1", "-p", "tcp", "--dport", port, "-j", "DROP", "-m", "comment", "--comment", "Vajra Rule")

	iptablesOutput, err := iptablesInCommand.CombinedOutput()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	iptablesOutOutput, err := iptablesOutCommand.CombinedOutput()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println("Command Output:", string(iptablesOutput))
	fmt.Println("Command Output:", string(iptablesOutOutput))

}

func isolateWithIPTables(port string) {

	port_int, err := strconv.Atoi(port)
	range1 := strconv.Itoa(port_int - 1)
	range2 := strconv.Itoa(port_int + 1)
	// blockPort("1:" + range1)
	// blockPort(range2 + ":65535")
	allowCmd := exec.Command("sudo", "iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", port, "-m", "comment", "--comment", "Vajra Isolate", "-j", "ACCEPT")
	allowCmdOut := exec.Command("sudo", "iptables", "-I", "OUTPUT", "1", "-p", "tcp", "--dport", port, "-m", "comment", "--comment", "Vajra Isolate", "-j", "ACCEPT")
	iptablesInCommand := exec.Command("sudo", "iptables", "-I", "INPUT", "2", "-p", "tcp", "--dport", "1:"+range1, "-j", "DROP", "-m", "comment", "--comment", "Vajra Isolate")
	iptablesOutCommand := exec.Command("sudo", "iptables", "-I", "OUTPUT", "2", "-p", "tcp", "--dport", "1:"+range1, "-j", "DROP", "-m", "comment", "--comment", "Vajra Isolate")
	iptablesInCommandrange2 := exec.Command("sudo", "iptables", "-I", "INPUT", "2", "-p", "tcp", "--dport", range2+":65535", "-j", "DROP", "-m", "comment", "--comment", "Vajra Isolate")
	iptablesOutCommandrange2 := exec.Command("sudo", "iptables", "-I", "OUTPUT", "2", "-p", "tcp", "--dport", range2+":65535", "-j", "DROP", "-m", "comment", "--comment", "Vajra Isolate")

	iptablesOutput, err := iptablesInCommand.CombinedOutput()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	iptablesOutOutput, err := iptablesOutCommand.CombinedOutput()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	iptablesOutputrange2, err := iptablesInCommandrange2.CombinedOutput()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	iptablesOutOutputrange2, err := iptablesOutCommandrange2.CombinedOutput()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	allowCmdOutput, err := allowCmd.CombinedOutput()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	allowCmdOutOutput, err := allowCmdOut.CombinedOutput()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println("Command Output:", string(iptablesOutput))
	fmt.Println("Command Output:", string(iptablesOutOutput))
	fmt.Println("Command Output:", string(iptablesOutputrange2))
	fmt.Println("Command Output:", string(iptablesOutOutputrange2))
	fmt.Println("Command Output:", string(allowCmdOutput))
	fmt.Println("Command Output:", string(allowCmdOutOutput))

}

func allowWithIPTables(port string) {
	iptablesCommand := exec.Command("iptables", "-D", "INPUT", "-p", "tcp", "--dport", port, "-j", "DROP", "-m", "comment", "--comment", "Vajra Rule")
	iptablesOutCommand := exec.Command("sudo", "iptables", "-D", "OUTPUT", "-p", "tcp", "--dport", port, "-j", "DROP", "-m", "comment", "--comment", "Vajra Rule")
	iptablesOutput, err := iptablesCommand.CombinedOutput()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	iptablesOutOutput, err := iptablesOutCommand.CombinedOutput()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println("Command Output:", string(iptablesOutput))
	fmt.Println("Command Output:", string(iptablesOutOutput))
}

func isUFWInstalled() bool {
	// _, err := exec.LookPath("ufw")
	// return err == nil
	return false
}

func isUFWEnabled() bool {
	// statusCommand := exec.Command("ufw", "status")
	// output, err := statusCommand.CombinedOutput()
	// if err != nil {
	// 	return false
	// }
	// return strings.Contains(string(output), "Status: active")
	return false
}

func enableUFW() bool {
	enableCommand := exec.Command("ufw", "enable")
	err := enableCommand.Run()
	return err == nil
}

func extractPortNumber(s string) string {
	var port string
	for _, r := range s {
		if unicode.IsDigit(r) {
			port += string(r)
		}
	}
	return port
}

func checkUfwRules() ([]map[string]string, error) {
	cmd := exec.Command("sudo", "ufw", "status", "verbose")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	var rules []map[string]string

	for _, line := range lines {
		// Use TrimSpace to remove leading and trailing spaces
		line = strings.TrimSpace(line)

		// Skip empty lines and headers
		if line == "" || strings.HasPrefix(line, "Status:") || strings.HasPrefix(line, "To") || strings.HasPrefix(line, "Action:") {
			continue
		}

		// Split the line into parts
		parts := strings.Fields(line)
		if (len(parts) >= 3) && (strings.Contains(parts[1], "ALLOW") || strings.Contains(parts[1], "DENY")) {
			// Assuming 'proto', 'from', and 'port' fields are present
			rule := make(map[string]string)
			rule["port"] = extractPortNumber(parts[0])
			if parts[1] == "DENY" {
				rule["action"] = "block"
			} else {
				rule["action"] = strings.ToLower(parts[1])
			}
			// rule["message"] = parts[2]
			rules = append(rules, rule)
		}
	}

	uniquePorts := make(map[string]bool)
	var filteredRules []map[string]string

	for _, rule := range rules {
		port := rule["port"]
		if !uniquePorts[port] {
			uniquePorts[port] = true
			filteredRules = append(filteredRules, rule)
			print(filteredRules)
		}
	}
	return filteredRules, nil

}

func checkIpTablesRules() ([]map[string]string, error) {
	cmd := exec.Command("iptables", "-L", "-n", "-v")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	fmt.Println(lines) // Print the lines for debugging purposes
	var rules []map[string]string
	var currentRule map[string]string

	for _, line := range lines {
		// Skip header lines and empty lines
		if strings.HasPrefix(line, "Chain") || strings.TrimSpace(line) == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		// New rule entry
		if parts[0] == "Chain" {
			if currentRule != nil {
				rules = append(rules, currentRule)
			}
			currentRule = make(map[string]string) // Initialize currentRule as an empty map
		} else {
			// Assuming fields like 'pkts', 'bytes', and 'target' are present
			currentRule = make(map[string]string)
			currentRule[parts[len(parts)-1]] = strings.Join(parts[:len(parts)-1], " ")
		}
	}

	if currentRule != nil {
		rules = append(rules, currentRule)
	}

	return rules, nil
}

func PortBlockGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {

	var results []map[string]string

	actionConstraint, ok := queryContext.Constraints["action"]
	if !ok || len(actionConstraint.Constraints) == 0 {
		// No parameter is provided, return an error or take appropriate action
		// Check saved rules
		if isUFWEnabled() {
			firewallRules, err := checkUfwRules()
			if err != nil {
				return firewallRules, err
			}
			return firewallRules, err
		} else {
			firewallRules, err := checkIpTablesRules()
			if err != nil {
				return firewallRules, err
			}
			return firewallRules, err
		}

	}
	actionExpr, actionOK := queryContext.Constraints["action"]
	portExpr := queryContext.Constraints["port"]
	port := portExpr.Constraints[0].Expression
	action := strings.ToLower(actionExpr.Constraints[0].Expression)

	if actionOK && len(actionExpr.Constraints) > 0 {

		if action == "block" {
			// If "action" is "block" or "allow", add the specific port and action to blockRules
			// blockcmd := exec.Command("sudo", "ufw", "deny", port)
			// err := blockcmd.Run()
			blockPort(port)
			result := map[string]string{
				"port":    port,
				"action":  action,
				"reason":  "Vajra Rule",
				"message": "success",
			}
			results = append(results, result)
		} else if action == "allow" {
			// allowcmd := exec.Command("sudo", "ufw", "delete", "deny", port)
			// err := allowcmd.Run()
			// if err != nil {
			// 	return nil, err
			// }
			allowPort(port)
			result := map[string]string{
				"port":    port,
				"action":  action,
				"reason":  "Vajra Rule",
				"message": "success",
			}
			results = append(results, result)
		} else if action == "isolate" {
			// allowPort(port)
			// port_int, err := strconv.Atoi(port)
			// range1 := strconv.Itoa(port_int - 1)
			// range2 := strconv.Itoa(port_int + 1)
			// print(err)
			// blockPort("1:" + range1)
			// blockPort(range2 + ":65535")
			isolateWithIPTables(port)
			result := map[string]string{
				"port":    port,
				"action":  action,
				"reason":  "Vajra Rule",
				"message": "success",
			}
			results = append(results, result)
		} else if action == "reenroll" {
			// allowPort(port)
			port_int, err := strconv.Atoi(port)
			range1 := strconv.Itoa(port_int - 1)
			range2 := strconv.Itoa(port_int + 1)
			print(err)
			allowPort("1:" + range1)
			allowPort(range2 + ":65535")
			result := map[string]string{
				"port":    port,
				"action":  action,
				"reason":  "Vajra Rule",
				"message": "success",
			}
			results = append(results, result)
		} else {
			fmt.Print(action)
		}
	}
	return results, nil
}
