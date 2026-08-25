// Command tokens measures the generated documentation set (P6-17).
//
// The number this prints has been quoted in progress rows and in `llms.txt` for
// months, and until now the invocation that produced it existed only as a
// sentence somebody wrote down. A number that cannot be reproduced is an
// estimate wearing a measurement's clothes, which is the class of unrecorded
// provenance this project refuses everywhere else.
//
// So: a committed command. And it separates two things the old sentence ran
// together.
//
//   - **Measured**: bytes, characters and lines. Exact, reproducible, and
//     nobody's opinion.
//   - **Estimated**: tokens. A token count is a property of a *tokenizer*, and
//     different models tokenize the same file differently — the divisor here is
//     an average over English prose with code fences, which is what this corpus
//     is, and it is stated rather than buried.
//
// A real count is available to anybody who has a tokenizer, without this project
// taking a dependency on one: set KELYFOS_TOKENIZER to a command that reads the
// file on stdin and prints a number, and that number is reported as measured
// with the command that produced it named beside it.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/p4r4n0rm4l/KelyfOS/internal/docsize"
)

// charsPerToken is the divisor, named rather than hidden.
//
// It is literally the same constant tools/gendocs prints with — one declaration
// in internal/docsize, imported by both — so the two cannot disagree about the
// same file. They used to be two constants holding the same value, which is a
// different and weaker thing (P6-17). Changing it changes an estimate and
// nothing else, and the output says so.
const charsPerToken = docsize.CharsPerToken

func main() {
	quiet := flag.Bool("quiet", false, "print only the token figure")
	flag.Parse()

	files := flag.Args()
	if len(files) == 0 {
		files = []string{"llms-full.txt"}
	}

	for _, path := range files {
		body, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tokens: %v\n", err)
			os.Exit(1)
		}
		chars := utf8.RuneCount(body)
		lines := bytes.Count(body, []byte{'\n'})
		est := float64(chars) / charsPerToken

		if measured, by, ok := realCount(body); ok {
			if *quiet {
				fmt.Println(measured)
				continue
			}
			fmt.Printf("%s\n", path)
			fmt.Printf("  measured   %d bytes · %d characters · %d lines\n", len(body), chars, lines)
			fmt.Printf("  measured   %d tokens, by %s\n", measured, by)
			continue
		}

		if *quiet {
			fmt.Printf("%.0f\n", est)
			continue
		}
		fmt.Printf("%s\n", path)
		fmt.Printf("  measured   %d bytes · %d characters · %d lines\n", len(body), chars, lines)
		fmt.Printf("  estimated  ~%.0f tokens, at %.2f characters each\n", est, charsPerToken)
		fmt.Printf("             An estimate, because a token count belongs to a tokenizer and this\n")
		fmt.Printf("             project depends on none. For a measured one, point KELYFOS_TOKENIZER\n")
		fmt.Printf("             at a command that reads the file on stdin and prints a number.\n")
	}
}

// realCount asks an external tokenizer, when the operator named one.
//
// Deliberately not a dependency: a tokenizer pinned here would be one model's
// answer presented as the answer, and it would need updating every time that
// model changed. Naming the command in the environment keeps the choice with
// whoever cares about the number.
func realCount(body []byte) (int, string, bool) {
	spec := os.Getenv("KELYFOS_TOKENIZER")
	if spec == "" {
		return 0, "", false
	}
	fields := strings.Fields(spec)
	cmd := exec.Command(fields[0], fields[1:]...)
	cmd.Stdin = bytes.NewReader(body)
	out, err := cmd.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "tokens: KELYFOS_TOKENIZER (%s) failed: %v\n", spec, err)
		return 0, "", false
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "tokens: KELYFOS_TOKENIZER (%s) printed %q, not a number\n",
			spec, strings.TrimSpace(string(out)))
		return 0, "", false
	}
	return n, spec, true
}
