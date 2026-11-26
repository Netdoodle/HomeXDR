package vuln

import (
	"math"
	"strings"
)

// cvssInfo is what HomeXDR reads from a CVSS vector.
type cvssInfo struct {
	Score  float64
	Vector string
	// AttackVector is network, adjacent, local or physical.
	AttackVector string
	// Approximate is set for a CVSS 4.0 vector, which is scored with the 3.1 formula from
	// the metrics the two versions share. CVSS 4.0's own scoring needs a large lookup table.
	Approximate bool
}

// parseCVSS scores a CVSS 3.x vector exactly and a 4.0 vector approximately. ok is false for
// anything else.
func parseCVSS(vector string) (cvssInfo, bool) {
	vector = strings.TrimSpace(vector)
	parts := strings.Split(vector, "/")
	if len(parts) < 2 {
		return cvssInfo{}, false
	}
	m := map[string]string{}
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, ":")
		if ok {
			m[k] = v
		}
	}
	info := cvssInfo{Vector: vector}
	switch {
	case strings.HasPrefix(parts[0], "CVSS:3"):
	case parts[0] == "CVSS:4.0":
		info.Approximate = true
		// Map the 4.0 metrics onto 3.1's: attack requirements stand in for complexity, user
		// interaction is any UI other than none, and the vulnerable system's impact is C/I/A.
		// A subsequent-system impact of high counts as a scope change.
		if m["AT"] == "P" {
			m["AC"] = "H"
		}
		if m["UI"] == "P" || m["UI"] == "A" {
			m["UI"] = "R"
		}
		m["C"], m["I"], m["A"] = m["VC"], m["VI"], m["VA"]
		m["S"] = "U"
		if m["SC"] == "H" || m["SI"] == "H" || m["SA"] == "H" {
			m["S"] = "C"
		}
	default:
		return cvssInfo{}, false
	}
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	ac := map[string]float64{"L": 0.77, "H": 0.44}
	ui := map[string]float64{"N": 0.85, "R": 0.62}
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	names := map[string]string{"N": "network", "A": "adjacent", "L": "local", "P": "physical"}
	vAV, ok1 := av[m["AV"]]
	vAC, ok2 := ac[m["AC"]]
	vUI, ok3 := ui[m["UI"]]
	vC, ok4 := cia[m["C"]]
	vI, ok5 := cia[m["I"]]
	vA, ok6 := cia[m["A"]]
	changed := m["S"] == "C"
	var vPR float64
	ok7 := true
	switch m["PR"] {
	case "N":
		vPR = 0.85
	case "L":
		vPR = 0.62
		if changed {
			vPR = 0.68
		}
	case "H":
		vPR = 0.27
		if changed {
			vPR = 0.5
		}
	default:
		ok7 = false
	}
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) {
		return cvssInfo{}, false
	}
	info.AttackVector = names[m["AV"]]
	iss := 1 - (1-vC)*(1-vI)*(1-vA)
	var impact float64
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	exploit := 8.22 * vAV * vAC * vPR * vUI
	if impact <= 0 {
		info.Score = 0
		return info, true
	}
	if changed {
		info.Score = roundUp(math.Min(1.08*(impact+exploit), 10))
	} else {
		info.Score = roundUp(math.Min(impact+exploit, 10))
	}
	return info, true
}

// roundUp is CVSS 3.1's Roundup: the smallest number with one decimal that is not less than x.
func roundUp(x float64) float64 {
	i := int64(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return float64(i/10000+1) / 10
}
