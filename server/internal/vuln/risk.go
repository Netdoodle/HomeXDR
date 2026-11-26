package vuln

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// Risk = CVSS × likelihood ÷ 10. CVSS says how bad a flaw is if used; likelihood (0-10) says
// how likely it is to be used against this host, from facts HomeXDR can check: whether the host
// takes connections from the internet, how the flaw is attacked, whether CISA has seen it used,
// and FIRST's prediction of exploitation. No AI is involved, and the same facts always give the
// same score.

// Exposure says whether a host takes connections from the internet.
const (
	ExposureInternet = "internet"
	ExposureLAN      = "lan"
)

// Bands of the risk score.
const (
	BandCritical = "critical"
	BandHigh     = "high"
	BandMedium   = "medium"
	BandLow      = "low"
)

// riskInput is what the score is made from.
type riskInput struct {
	CVSS         float64
	AttackVector string // network, adjacent, local, physical or ""
	Exposure     string
	Ports        []int
	EPSS         float64 // 0..1, or -1 when unknown
	KEV          bool
	Ransomware   bool
}

// riskResult is the score and why.
type riskResult struct {
	Likelihood float64
	Risk       float64
	Band       string
	Reasons    []string
}

func round1(x float64) float64 { return math.Round(x*10) / 10 }

func band(risk float64) string {
	switch {
	case risk >= 8:
		return BandCritical
	case risk >= 6:
		return BandHigh
	case risk >= 3:
		return BandMedium
	}
	return BandLow
}

func portList(ports []int) string {
	p := append([]int(nil), ports...)
	sort.Ints(p)
	if len(p) > 6 {
		p = p[:6]
	}
	s := make([]string, len(p))
	for i, x := range p {
		s[i] = fmt.Sprint(x)
	}
	out := strings.Join(s, ", ")
	if len(ports) > 6 {
		out += ", …"
	}
	return out
}

func score(in riskInput) riskResult {
	var l float64
	var reasons []string
	internet := in.Exposure == ExposureInternet
	switch in.AttackVector {
	case "local":
		l = 1.5
		reasons = append(reasons, "The flaw can only be used by someone already running code on the host.")
	case "physical":
		l = 0.5
		reasons = append(reasons, "The flaw needs physical access to the machine.")
	case "adjacent":
		l = 2.5
		if internet {
			l = 3.5
		}
		reasons = append(reasons, "The flaw can only be attacked from the same local network segment.")
	default:
		if internet {
			l = 7
			if in.AttackVector == "network" {
				reasons = append(reasons, fmt.Sprintf("The host takes connections from the internet (port %s), and the flaw can be attacked over the network.", portList(in.Ports)))
			} else {
				reasons = append(reasons, fmt.Sprintf("The host takes connections from the internet (port %s). How the flaw is attacked is not known, so it is treated as reachable.", portList(in.Ports)))
			}
		} else {
			l = 3
			reasons = append(reasons, "The host takes no connections from the internet, so an attacker would first need a foothold inside your network.")
		}
	}
	if internet && in.AttackVector != "" && in.AttackVector != "network" {
		reasons = append(reasons, fmt.Sprintf("The host does take connections from the internet (port %s), which helps an attacker get close.", portList(in.Ports)))
	}
	switch {
	case in.EPSS >= 0.5:
		l += 3
	case in.EPSS >= 0.1:
		l += 2
	case in.EPSS >= 0.01:
		l += 1
	}
	if in.EPSS >= 0 {
		pct := in.EPSS * 100
		switch {
		case in.EPSS >= 0.01:
			reasons = append(reasons, fmt.Sprintf("FIRST predicts a %.1f%% chance it is exploited in the next 30 days, which is high for a CVE.", pct))
		default:
			reasons = append(reasons, fmt.Sprintf("FIRST predicts a %.2f%% chance it is exploited in the next 30 days.", pct))
		}
	}
	if in.KEV {
		if internet && (in.AttackVector == "network" || in.AttackVector == "") {
			l = math.Max(l, 9.5)
		} else {
			l += 3
		}
		reasons = append(reasons, "CISA knows it is being exploited.")
		if in.Ransomware {
			l += 0.5
			reasons = append(reasons, "It is known to be used in ransomware campaigns.")
		}
	}
	l = round1(math.Min(10, math.Max(0.5, l)))
	risk := round1(in.CVSS * l / 10)
	return riskResult{Likelihood: l, Risk: risk, Band: band(risk), Reasons: reasons}
}
