// Package docsize holds the one constant two commands print the same number
// with (P6-17).
//
// `tools/gendocs` prints a token estimate for llms-full.txt when it regenerates
// it, and `tools/tokens` prints one on demand. Until this package they each
// carried their own `const charsPerToken = 3.83`, and tools/tokens's own comment
// claimed they were "the same constant ... so the two cannot disagree about the
// same file" — which was not true of two independent constants that merely held
// the same value. Nothing stopped one being repinned without the other, and the
// failure mode is the quiet one: two commands reporting different sizes for one
// file, each correct by its own arithmetic.
//
// That is the second-copy-of-the-truth failure this project names everywhere
// else, in the task whose whole subject is a number that can be reproduced. So
// there is one constant now, and both commands import it.
package docsize

// CharsPerToken is the divisor, named rather than hidden.
//
// The ratio is measured rather than guessed: 3.83 characters per token, from
// encoding the generated corpus with tiktoken's cl100k_base and o200k_base at
// E3-2, which agreed to within 0.1% (48,285 and 48,244 tokens over 184,998
// characters). Characters and not bytes, because that is what a tokenizer sees
// and because this corpus is full of em dashes — counting its bytes would
// inflate the estimate by the width of its punctuation.
//
// Re-measured at the E4 exit, on a corpus that had grown by 61%: 298,395
// characters, 77,480 tokens (cl100k_base) and 77,447 (o200k_base), which is
// 3.851 and 3.853 characters per token. The pinned 3.83 is therefore 0.6% low
// per token and the printed estimate 0.6% high — the safe direction for a reader
// deciding whether this fits in a context window, and not enough drift to be
// worth repinning a number whose provenance is its value.
//
// The question the number answers is only "does this fit in a context window",
// and the measured counts with the commands that produced them are in the
// progress log, where a claim of that kind belongs.
const CharsPerToken = 3.83

// Estimate is the token estimate for a string, by the ratio above.
func Estimate(s string) int {
	return int(float64(len([]rune(s))) / CharsPerToken)
}
