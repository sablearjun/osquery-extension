// Vajra EDR client Isolation and Port blocking extension for Osquery
// Author: Arjun Sable, IEOR, IIT Bombay
// Date: 2023-07-25

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

var (
	// Osqueryi
	// socket = flag.String("socket", "\\\\.\\pipe\\shell.em", "Path to osquery socket file")

	// Osqueryd
	socket = flag.String("socket", "\\\\.\\pipe\\osquery.em", "Path to osquery socket file")
)

func main() {
	flag.Parse()

	// Osquery socket path
	if *socket == "" {
		log.Fatal("Missing socket path")
	}

	// Create a new extension manager
	manager, err := osquery.NewExtensionManagerServer("port_block", *socket)
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
	}
}

// PortBlockGenerate retrieves the port block rules from the extension's database table
func PortBlockGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	var results []map[string]string

	actionConstraint, ok := queryContext.Constraints["action"]
	if !ok || len(actionConstraint.Constraints) == 0 {
		// No parameter is provided, return an error or take appropriate action
		// Check saved rules
		firewallRules, err := checkFirewallRules()
		if err != nil {
			return nil, err
		}
		return firewallRules, err
	}
	actionExpr, actionOK := queryContext.Constraints["action"]
	portExpr, portOK := queryContext.Constraints["port"]

	// Default blockRules containing the predefined rules
	// blockRules := []map[string]string{}

	if actionOK && len(actionExpr.Constraints) > 0 {
		// If "action" parameter is provided, get its value
		action := strings.ToLower(actionExpr.Constraints[0].Expression)
		//ToDo if action == 'allow' then delete the previous rule
		if action == "block" {
			// If "action" is "block" or "allow", add the specific port and action to blockRules
			if portOK && len(portExpr.Constraints) > 0 {
				for i := 0; i < len(portExpr.Constraints); i++ {
					port := portExpr.Constraints[i].Expression
					successMsg, err := blockPortTraffic(port, action)
					if err != nil {
						return nil, err
					}
					result := map[string]string{
						"port":    port,
						"action":  action,
						"reason":  "Vajra Rule",
						"message": successMsg,
					}
					results = append(results, result)
				}
				return results, nil
			}
		} else if action == "allow" {
			for i := 0; i < len(portExpr.Constraints); i++ {
				port := portExpr.Constraints[i].Expression
				successMsg, err := allowPortTraffic(port, action)
				if err != nil {
					return nil, err
				}
				result := map[string]string{
					"port":    port,
					"action":  action,
					"reason":  "Vajra Rule",
					"message": successMsg,
				}
				results = append(results, result)
			}
			return results, nil
		} else if action == "isolate" {
			// If "action" is "isolate", add the predefined block rules to blockRules
			port := portExpr.Constraints[0].Expression
			isolateOk, err := isolateMachine(port)
			if err != nil {
				return nil, err
			}
			fmt.Println(isolateOk)
		} else if action == "reenroll" {
			// If "action" is "reenroll", call the function to delete the Firewall rules
			err := reenrollMachine()
			if err != nil {
				return nil, err
			}
		} else {
			return nil, fmt.Errorf("invalid action parameter, must be 'block', 'allow', 'isolate', or 'reenroll'")
		}
	}
	return results, nil
}

// blockPortTraffic blocks or allows traffic for the specified port using Windows Firewall API
func blockPortTraffic(port, action string) (string, error) {
	// Add firewall rule to block the traffic
	cmd := exec.Command("powershell", "-Command", fmt.Sprintf("New-NetFirewallRule -DisplayName 'Vajra Rule' -Direction 'Outbound' -RemotePort '%s' -Protocol 'TCP' -Action %s", port, strings.Title(action)))
	err := cmd.Run()
	if err != nil {
		return "fail", fmt.Errorf("failed to block port traffic: %v", err)
	}
	return "Port traffic blocked successfully!", nil
}

// allowPortTraffic blocks or allows traffic for the specified port using Windows Firewall API
func allowPortTraffic(port, action string) (string, error) {
	// Add firewall rule to allow the traffic
	cmd := exec.Command("powershell", "-Command", fmt.Sprintf(`$rules = Get-NetFirewallRule | Where-Object { $_.DisplayName -eq 'Vajra Rule' -and $_.Action -eq 'Block' }
	
	foreach ($rule in $rules) {
		$action = $rule | Select-Object -ExpandProperty Action
		$name = $rule | Select-Object -ExpandProperty Name
		$ports = $rule | Get-NetFirewallPortFilter
		$displayName = $rule | Select-Object -ExpandProperty DisplayName
		foreach ($port in $ports) {
				$remotePort =  $port | Select-Object -ExpandProperty RemotePort
				Write-Output "$remotePort"
			if ($remotePort -eq '%s' -and $action -eq 'Block') {
				Write-Output "$name"
				Remove-NetFirewallRule -Name $name
			}
			Write-Output "$action,$remotePort,$displayName"
		}
	}`, port))
	err := cmd.Run()
	if err != nil {
		return "fail", fmt.Errorf("failed to allow port traffic: %v", err)
	}
	return "Port traffic allowed successfully!", nil
}

// deleteFirewallRules deletes the Firewall rules with the display name 'Vajra Rule'
func deleteFirewallRules() error {
	// Delete the rule from firewall
	cmd := exec.Command("powershell", "-Command", "Get-NetFirewallRule | ? DisplayName -eq 'Vajra Rule' | Remove-NetFirewallRule")
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to delete Firewall rules: %v", err)
	}
	return nil
}

func isolateMachine(port string) (string, error) {
	// Isolate machine by adding rule to allow only one port and block all other ports
	isolateRules := []map[string]string{
		{
			"port":   port,
			"action": "allow",
		},
		{
			"port":   "1-1233",
			"action": "block",
		},
		{
			"port":   "1235-65535",
			"action": "block",
		},
	}
	// Apply the isolate rules using Windows Firewall API
	for _, rule := range isolateRules {
		cmd := exec.Command("powershell", "-Command", fmt.Sprintf("New-NetFirewallRule -DisplayName 'Vajra Isolate' -Direction 'Outbound' -RemotePort '%s' -Protocol 'TCP' -Action %s", rule["port"], strings.Title(rule["action"])))
		err := cmd.Run()
		if err != nil {
			return "fail", fmt.Errorf("failed to isolate: %v", err)
		}
	}
	return "Machine isolated successfully!", nil
}

// deleteFirewallRules deletes the Firewall rules with the display name 'Vajra Rule'
func reenrollMachine() error {
	// Implement your logic to delete the Firewall rules with the display name 'Vajra Rule'
	// You can use appropriate Windows Firewall libraries or APIs to achieve this

	// Example implementation using PowerShell command:
	cmd := exec.Command("powershell", "-Command", "Get-NetFirewallRule | ? DisplayName -eq 'Vajra Isolate' | Remove-NetFirewallRule")
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to reenroll: %v", err)
	}

	return nil
}

// Check active rules
func checkFirewallRules() ([]map[string]string, error) {
	cmd := exec.Command("powershell", "-Command", `
	$rules = Get-NetFirewallRule | Where-Object { $_.DisplayName -eq 'Vajra Rule' -or $_.DisplayName -eq 'Vajra Isolate' }
	
	foreach ($rule in $rules) {
		$action = $rule | Select-Object -ExpandProperty Action
		$ports = $rule | Get-NetFirewallPortFilter
		$displayName = $rule | Select-Object -ExpandProperty DisplayName
		foreach ($port in $ports) {
			$remotePort = $port | Select-Object -ExpandProperty RemotePort
			Write-Output "$action,$remotePort,$displayName"
		}
	}
	`)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to run PowerShell script: %v", err)
	}

	// Parse the output and create a table
	var result []map[string]string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Split(line, ",")
		if len(fields) == 3 {
			entry := map[string]string{
				"action": fields[0],
				"port":   strings.ReplaceAll(fields[1], "\r", ""),
				"reason": strings.ReplaceAll(fields[2], "\r", ""),
			}
			result = append(result, entry)
		}
	}

	return result, nil
}
