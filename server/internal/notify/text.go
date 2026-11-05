package notify

import (
	"regexp"
	"strings"
	"unicode"
)

var httpWord = regexp.MustCompile(`(?i)\bhttp`)

// Defang makes indicators in text inert, so nothing in a chat or a mail app turns into a
// link: hxxp, [://] and example[.]com. A dot counts only between letters or digits, which
// leaves the end of a sentence alone. The idea is from tapwatch's notifiers.
func Defang(s string) string {
	s = httpWord.ReplaceAllStringFunc(s, func(m string) string {
		if m[0] == 'H' {
			return "HXXP"
		}
		return "hxxp"
	})
	s = strings.ReplaceAll(s, "://", "[://]")
	var b strings.Builder
	b.Grow(len(s))
	rs := []rune(s)
	for i, r := range rs {
		if r == '.' && i > 0 && i+1 < len(rs) && isWordRune(rs[i-1]) && isWordRune(rs[i+1]) {
			b.WriteString("[.]")
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func isWordRune(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }

// clean removes what alert content must not smuggle into a message: control characters,
// and invisible or direction-changing characters that disguise text. Newlines survive
// only when multiline is set, so a value cannot fake extra lines in a message.
func clean(s string, multiline bool) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			if multiline {
				b.WriteRune(r)
			} else {
				b.WriteRune(' ')
			}
		case r == '\r':
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), r == unicode.ReplacementChar:
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// shorten cuts s to at most n bytes on a character boundary.
func shorten(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !isRuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }

// untrusted prepares a value from an alert for a message: one line, short, and inert.
func untrusted(s string, n int) string {
	return Defang(shorten(clean(s, false), n))
}

var discordSpecial = strings.NewReplacer(
	`\`, `\\`, `*`, `\*`, `_`, `\_`, "`", "\\`", `~`, `\~`, `|`, `\|`, `>`, `\>`, `#`, `\#`,
	`[`, `\[`, `]`, `\]`, `(`, `\(`, `)`, `\)`, `@`, `\@`, `<`, `\<`,
)

// discordEscape stops Discord from treating text as markdown or a mention.
func discordEscape(s string) string { return discordSpecial.Replace(s) }
