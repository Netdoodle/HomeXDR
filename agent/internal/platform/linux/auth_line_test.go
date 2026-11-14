//go:build linux

package linux

import (
	"bufio"
	"io"
	"strings"
	"testing"
)

func TestReadJournalLineSkipsOversize(t *testing.T) {
	in := "first\n" + strings.Repeat("x", maxJournalLine+10) + "\nlast\r\n"
	br := bufio.NewReaderSize(strings.NewReader(in), 4096)
	type res struct {
		line    string
		tooLong bool
	}
	var got []res
	for {
		line, tooLong, err := readJournalLine(br)
		if err != nil {
			if err != io.EOF {
				t.Fatal(err)
			}
			break
		}
		got = append(got, res{string(line), tooLong})
	}
	if len(got) != 3 || got[0] != (res{"first", false}) || !got[1].tooLong || got[1].line != "" || got[2] != (res{"last", false}) {
		t.Fatalf("lines = %d, first %+v, last %+v", len(got), got[0], got[len(got)-1])
	}
}
