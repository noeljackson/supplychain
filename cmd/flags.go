package cmd

import (
	"errors"
	"flag"
	"os"
	"strings"
)

// parseFlags accepts subcommand flags before or after positional arguments.
// A literal -- still ends option parsing, including for dash-prefixed paths.
func parseFlags(fs *flag.FlagSet, args []string) error {
	var options, positional []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			positional = append(positional, arg)
			continue
		}
		options = append(options, arg)
		name := strings.TrimLeft(arg, "-")
		if strings.Contains(name, "=") {
			continue
		}
		option := fs.Lookup(name)
		if option == nil {
			continue // Let flag.Parse report unknown flags and handle -h/--help.
		}
		boolean, ok := option.Value.(interface{ IsBoolFlag() bool })
		if ok && boolean.IsBoolFlag() {
			continue
		}
		if i+1 < len(args) {
			i++
			options = append(options, args[i])
		} else {
			return fs.Parse(options) // Do not turn the end marker into a missing value.
		}
	}
	return fs.Parse(append(append(options, "--"), positional...))
}

func flagExit(err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	return 2
}

func pathArgs(name string, args []string) ([]string, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := parseFlags(fs, args); err != nil {
		return nil, err
	}
	return fs.Args(), nil
}
