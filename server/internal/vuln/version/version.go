// Package version compares package versions the way each distro's package manager does:
// dpkg (Debian, Ubuntu), apk (Alpine) and rpm (RHEL, Rocky, Alma, Fedora, SUSE). Plain
// semver comparison gets these wrong (epochs, tildes, revisions), and a wrong comparison
// turns a fixed package into a false finding or hides a real one.
package version

import "strings"

// Compare compares a and b with the rules of the given package kind: "deb", "apk" or
// "rpm". It returns -1, 0 or 1; ok is false for an unknown kind.
func Compare(ecosystemKind, a, b string) (int, bool) {
	switch ecosystemKind {
	case "deb":
		return CompareDpkg(a, b), true
	case "apk":
		return CompareAPK(a, b), true
	case "rpm":
		return CompareRPM(a, b), true
	}
	return 0, false
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// cmpDigits compares two runs of digits numerically without overflow.
func cmpDigits(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

// digitRun returns the leading digits of s.
func digitRun(s string) string {
	i := 0
	for i < len(s) && isDigit(s[i]) {
		i++
	}
	return s[:i]
}

// splitEpoch splits "[epoch:]rest". An epoch is only recognised when it is all digits.
func splitEpoch(v string) (epoch, rest string) {
	if i := strings.IndexByte(v, ':'); i > 0 && digitRun(v[:i]) == v[:i] {
		return v[:i], v[i+1:]
	}
	return "0", v
}

// ---- dpkg ----

// CompareDpkg compares Debian/Ubuntu versions: [epoch:]upstream[-revision], the revision
// being what follows the last hyphen.
func CompareDpkg(a, b string) int {
	ea, ra := splitEpoch(strings.TrimSpace(a))
	eb, rb := splitEpoch(strings.TrimSpace(b))
	if c := cmpDigits(ea, eb); c != 0 {
		return c
	}
	ua, rva := splitRevision(ra)
	ub, rvb := splitRevision(rb)
	if c := dpkgPart(ua, ub); c != 0 {
		return c
	}
	return dpkgPart(rva, rvb)
}

func splitRevision(v string) (upstream, revision string) {
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return v[:i], v[i+1:]
	}
	return v, ""
}

// dpkgOrder is dpkg's character weight: '~' before everything (even the end), then the end
// of the string, then letters, then every other character.
func dpkgOrder(s string, i int) int {
	if i >= len(s) {
		return 0
	}
	c := s[i]
	switch {
	case isDigit(c):
		return 0
	case isAlpha(c):
		return int(c)
	case c == '~':
		return -1
	}
	return int(c) + 256
}

// dpkgPart is dpkg's verrevcmp: alternating non-digit and digit runs.
func dpkgPart(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			oa, ob := dpkgOrder(a, i), dpkgOrder(b, j)
			if oa != ob {
				if oa < ob {
					return -1
				}
				return 1
			}
			i++
			j++
		}
		da, db := digitRun(a[min(i, len(a)):]), digitRun(b[min(j, len(b)):])
		if c := cmpDigits(da, db); c != 0 {
			return c
		}
		i += len(da)
		j += len(db)
	}
	return 0
}

// ---- rpm ----

// CompareRPM compares [epoch:]version[-release] with rpmvercmp. When either side has no
// release the release is not compared.
func CompareRPM(a, b string) int {
	ea, ra := splitEpoch(strings.TrimSpace(a))
	eb, rb := splitEpoch(strings.TrimSpace(b))
	if c := cmpDigits(ea, eb); c != 0 {
		return c
	}
	va, rela := splitRevision(ra)
	vb, relb := splitRevision(rb)
	if c := rpmvercmp(va, vb); c != 0 {
		return c
	}
	if rela == "" || relb == "" {
		return 0
	}
	return rpmvercmp(rela, relb)
}

func isAlnum(c byte) bool { return isDigit(c) || isAlpha(c) }

// rpmvercmp is rpm's version segment comparison, including '~' and '^' (rpm >= 4.15).
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	for len(a) > 0 || len(b) > 0 {
		for len(a) > 0 && !isAlnum(a[0]) && a[0] != '~' && a[0] != '^' {
			a = a[1:]
		}
		for len(b) > 0 && !isAlnum(b[0]) && b[0] != '~' && b[0] != '^' {
			b = b[1:]
		}
		if (len(a) > 0 && a[0] == '~') || (len(b) > 0 && b[0] == '~') {
			if len(a) == 0 || a[0] != '~' {
				return 1
			}
			if len(b) == 0 || b[0] != '~' {
				return -1
			}
			a, b = a[1:], b[1:]
			continue
		}
		if (len(a) > 0 && a[0] == '^') || (len(b) > 0 && b[0] == '^') {
			if len(a) == 0 {
				return -1
			}
			if len(b) == 0 {
				return 1
			}
			if a[0] != '^' {
				return 1
			}
			if b[0] != '^' {
				return -1
			}
			a, b = a[1:], b[1:]
			continue
		}
		if len(a) == 0 || len(b) == 0 {
			break
		}
		num := isDigit(a[0])
		var sa, sb string
		if num {
			sa, sb = digitRun(a), digitRun(b)
		} else {
			sa, sb = alphaRun(a), alphaRun(b)
		}
		if sb == "" {
			// The other side holds a different kind of segment: numeric is newer.
			if num {
				return 1
			}
			return -1
		}
		if num {
			if c := cmpDigits(sa, sb); c != 0 {
				return c
			}
		} else if c := strings.Compare(sa, sb); c != 0 {
			return c
		}
		a, b = a[len(sa):], b[len(sb):]
	}
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) > 0:
		return 1
	}
	return -1
}

func alphaRun(s string) string {
	i := 0
	for i < len(s) && isAlpha(s[i]) {
		i++
	}
	return s[:i]
}

// ---- apk ----

type apkSuffix struct {
	rank int
	num  string
}

type apkVersion struct {
	nums     []string
	letter   byte
	suffixes []apkSuffix
	rev      string
}

var apkSuffixRank = map[string]int{
	"alpha": -4, "beta": -3, "pre": -2, "rc": -1,
	"cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5,
}

// parseAPK reads 1.2.3a_rc1_p2-r4 leniently; anything it does not understand ends the parse.
func parseAPK(s string) apkVersion {
	var v apkVersion
	s = strings.TrimSpace(s)
	i := 0
	for i < len(s) {
		d := digitRun(s[i:])
		if d == "" {
			break
		}
		v.nums = append(v.nums, d)
		i += len(d)
		if i+1 < len(s) && s[i] == '.' && isDigit(s[i+1]) {
			i++
			continue
		}
		break
	}
	if i < len(s) && s[i] >= 'a' && s[i] <= 'z' {
		v.letter = s[i]
		i++
	}
	for i < len(s) && s[i] == '_' {
		j := i + 1
		for j < len(s) && s[j] >= 'a' && s[j] <= 'z' {
			j++
		}
		rank, ok := apkSuffixRank[s[i+1:j]]
		if !ok {
			break
		}
		d := digitRun(s[j:])
		v.suffixes = append(v.suffixes, apkSuffix{rank, d})
		i = j + len(d)
	}
	if strings.HasPrefix(s[i:], "-r") {
		v.rev = digitRun(s[i+2:])
	}
	return v
}

// CompareAPK compares Alpine versions: 1.2.3a_rc1-r4.
func CompareAPK(a, b string) int {
	va, vb := parseAPK(a), parseAPK(b)
	for i := 0; i < len(va.nums) && i < len(vb.nums); i++ {
		x, y := va.nums[i], vb.nums[i]
		var c int
		if i > 0 && (x[0] == '0' || y[0] == '0') {
			c = strings.Compare(x, y) // fractional parts compare as text: 1.01 < 1.1
		} else {
			c = cmpDigits(x, y)
		}
		if c != 0 {
			return c
		}
	}
	if len(va.nums) != len(vb.nums) {
		if len(va.nums) < len(vb.nums) {
			return -1
		}
		return 1
	}
	if va.letter != vb.letter {
		if va.letter < vb.letter {
			return -1
		}
		return 1
	}
	for i := 0; i < len(va.suffixes) || i < len(vb.suffixes); i++ {
		var x, y apkSuffix
		if i < len(va.suffixes) {
			x = va.suffixes[i]
		}
		if i < len(vb.suffixes) {
			y = vb.suffixes[i]
		}
		if x.rank != y.rank {
			if x.rank < y.rank {
				return -1
			}
			return 1
		}
		if c := cmpDigits(x.num, y.num); c != 0 {
			return c
		}
	}
	return cmpDigits(va.rev, vb.rev)
}
