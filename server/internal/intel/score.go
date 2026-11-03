package intel

import (
	"fmt"
	"math"
	"slices"
	"strings"
)

// Verdicts.
const (
	VerdictMalicious  = "malicious"
	VerdictSuspicious = "suspicious"
	VerdictLow        = "low"       // weak signals only
	VerdictClean      = "clean"     // a strong source looked and found nothing
	VerdictNoSignal   = "no_signal" // only weak sources had data, and it is not bad
	VerdictUnknown    = "unknown"   // no reputation source knows it
	VerdictInternal   = "internal"  // private: never sent to any service
)

// Coverage counts how the sources answered.
type Coverage struct {
	Checked  int `json:"checked"` // sources that answered or are answering
	WithData int `json:"with_data"`
	NoData   int `json:"no_data"`
	NeedsKey int `json:"needs_key"`
	Failed   int `json:"failed"`
	Pending  int `json:"pending"`
}

// Summary combines the sources' answers.
type Summary struct {
	Score    *int     `json:"score,omitempty"` // 0-100; none without reputation data
	Verdict  string   `json:"verdict"`
	Basis    string   `json:"basis"` // what the score rests on
	Brief    []string `json:"brief"` // short paragraphs
	Geo      *Geo     `json:"geo,omitempty"`
	Whois    *Whois   `json:"whois,omitempty"`
	Coverage Coverage `json:"coverage"`
}

func sourceProviderName(id string) string {
	for _, s := range Sources {
		if s.ID == id {
			return providerByID(s.Provider).Name
		}
	}
	return id
}

func sourceWeight(id string) int {
	for _, s := range Sources {
		if s.ID == id {
			return s.Weight
		}
	}
	return 0
}

// nameList joins names as prose: "A, B and C".
func nameList(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

// score weighs the strongest signal over the average: one solid report outweighs sources
// that simply have not seen an indicator, which plain averaging would hide.
func score(results []Result) (*int, string, string) {
	var sum, weights float64
	var strongest, strongestWeak float64
	strongName, strongWeakName := "", ""
	var names []string
	strong := false
	for _, r := range results {
		if r.State != StateOK || r.Risk == nil {
			continue
		}
		w := max(sourceWeight(r.Source), 1)
		risk := float64(*r.Risk)
		sum += risk * float64(w)
		weights += float64(w)
		names = append(names, r.Name)
		if w >= 2 {
			strong = true
			if risk >= strongest {
				strongest, strongName = risk, r.Name
			}
		}
		if risk >= strongestWeak {
			strongestWeak, strongWeakName = risk, r.Name
		}
	}
	if weights == 0 {
		return nil, VerdictUnknown, "No reputation source had data on it."
	}
	if !strong {
		strongest, strongName = strongestWeak, strongWeakName
	}
	v := int(math.Round(0.6*strongest + 0.4*sum/weights))
	basis := "From " + nameList(names) + "."
	if strongest > 0 {
		basis += fmt.Sprintf(" Strongest signal: %s (%d).", strongName, int(strongest))
	}
	verdict := VerdictClean
	switch {
	case v >= 75:
		verdict = VerdictMalicious
	case v >= 45:
		verdict = VerdictSuspicious
	case v >= 20:
		verdict = VerdictLow
	case !strong:
		verdict = VerdictNoSignal
	}
	return &v, verdict, basis
}

// summarize builds the summary of a set of results.
func summarize(ind Indicator, results []Result) Summary {
	if ind.Private {
		return Summary{Verdict: VerdictInternal, Basis: "Not sent to any external service.",
			Brief: []string{ind.Value + " is a private address or internal name, so it was not sent to any external service. Only your own data is searched."}}
	}
	var s Summary
	s.Score, s.Verdict, s.Basis = score(results)
	for _, r := range results {
		switch r.State {
		case StateOK:
			s.Coverage.Checked++
			s.Coverage.WithData++
		case StateNoData:
			s.Coverage.Checked++
			s.Coverage.NoData++
		case StateNeedsKey:
			s.Coverage.NeedsKey++
		case StatePending:
			s.Coverage.Pending++
		default:
			s.Coverage.Checked++
			s.Coverage.Failed++
		}
		if r.Geo != nil && s.Geo == nil {
			s.Geo = r.Geo
		}
		if r.Whois != nil && s.Whois == nil {
			s.Whois = r.Whois
		}
	}
	s.Brief = brief(ind, results, s)
	return s
}

// brief writes the assessment in plain sentences from what the sources said.
func brief(ind Indicator, results []Result, s Summary) []string {
	var high, strong, weak, failed, keys []string
	var evidence, context []string
	var age *int
	for _, r := range results {
		switch r.State {
		case StateNeedsKey:
			keys = append(keys, sourceProviderName(r.Source))
			continue
		case StateQuota:
			failed = append(failed, r.Name+" (over its quota)")
			continue
		case StateError:
			failed = append(failed, r.Name)
			continue
		case StateOK:
		default:
			continue
		}
		if r.DomainAgeDays != nil && age == nil {
			age = r.DomainAgeDays
		}
		if r.Risk != nil {
			if *r.Risk >= 60 {
				high = append(high, r.Name)
			}
			if sourceWeight(r.Source) >= 2 {
				strong = append(strong, r.Name)
			} else {
				weak = append(weak, r.Name)
			}
			if *r.Risk >= 40 || r.Benign {
				evidence = append(evidence, r.Name+": "+r.Headline+".")
			}
		}
		switch r.Source {
		case "proxycheck":
			if slices.ContainsFunc(r.Fields, func(f Field) bool { return f.Label == "Proxy" && f.Value == "yes" }) {
				context = append(context, r.Headline+".")
			}
		case "internetdb":
			if slices.ContainsFunc(r.Fields, func(f Field) bool { return f.Label == "CVEs" }) {
				context = append(context, "Shodan: "+r.Headline+".")
			}
		}
	}
	var out []string
	v := ind.Value
	switch s.Verdict {
	case VerdictMalicious:
		out = append(out, v+" looks malicious: "+nameList(high)+" report it.")
	case VerdictSuspicious:
		if len(high) > 0 {
			out = append(out, v+" looks suspicious: "+nameList(high)+" flag it.")
		} else {
			out = append(out, v+" looks suspicious: several sources show moderate signals.")
		}
	case VerdictLow:
		out = append(out, v+" has only weak signals against it. Weigh it against what you see in your own data.")
	case VerdictClean:
		out = append(out, v+" shows no sign of malicious activity in "+nameList(strong)+".")
	case VerdictNoSignal:
		out = append(out, "Nothing bad is known about "+v+", but only "+nameList(weak)+" had data, which is weak evidence.")
	default:
		out = append(out, "No reputation source has data on "+v+". That does not make it safe: new or targeted infrastructure often has no history.")
	}
	if len(evidence) > 0 {
		out = append(out, strings.Join(evidence[:min(len(evidence), 4)], " "))
	}
	if age != nil {
		switch {
		case *age < 30:
			context = append(context, fmt.Sprintf("The domain was registered %d days ago; brand-new domains are common in phishing and malware campaigns.", *age))
		case *age < 180:
			context = append(context, fmt.Sprintf("The domain is fairly new (%d days old).", *age))
		}
	}
	if len(context) > 0 {
		out = append(out, strings.Join(context, " "))
	}
	var gaps []string
	if len(keys) > 0 {
		keys = uniqNames(keys)
		verb := " needs"
		if len(keys) > 1 {
			verb = " need"
		}
		gaps = append(gaps, nameList(keys)+verb+" a free API key (Settings > Threat intel).")
	}
	if len(failed) > 0 {
		gaps = append(gaps, nameList(failed)+" could not answer.")
	}
	if len(gaps) > 0 {
		out = append(out, "For a firmer answer: "+strings.Join(gaps, " "))
	}
	return out
}

func uniqNames(names []string) []string {
	out := names[:0:0]
	for _, n := range names {
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}
