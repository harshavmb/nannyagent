package agent

import (
	"strings"
	"testing"
)

func TestExecuteCommands(t *testing.T) {
	a := NewAgent()
	commands := []string{
		"echo 'Hello, World!'",
		"echo 'Test Command'",
	}

	expectedOutput := "Hello, World!\n\nTest Command\n"
	output, err := a.ExecuteCommands(commands)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if output != expectedOutput {
		t.Fatalf("Expected %q, got %q", expectedOutput, output)
	}
}

func TestExecuteCommandsWithPID(t *testing.T) {
	a := NewAgent()
	commands := []string{
		"echo '1234' > /tmp/testpid",
		"cat /tmp/testpid",
	}

	expectedOutput := "\n1234\n"
	output, err := a.ExecuteCommands(commands)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if output != expectedOutput {
		t.Fatalf("Expected %q, got %q", expectedOutput, output)
	}
}

func TestGetGenerativeAIResponse(t *testing.T) {
	a := NewAgent()
	input := "what is the OS distro?"

	// Mock the Gemini API response
	expectedCommand := "/etc/os-release"

	commands, err := a.GetGenerativeAIResponse(input)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	count := 0
	for _, command := range commands {
		if strings.Contains(command, expectedCommand) {
			count++
		}
	}

	if count < 1 {
		t.Fatalf("Expected %v, to be in %v", expectedCommand, commands)
	}

}
