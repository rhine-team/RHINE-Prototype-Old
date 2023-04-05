package rhine

import (
	"context"
	"strings"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin/file/rrutil"
	"github.com/coredns/coredns/plugin/file/tree"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

// Result is the result of a Lookup
type Result int

const (
	// Success is a successful lookup.
	Success Result = iota
	// NameError indicates a nameerror
	NameError
	// Delegation indicates the lookup resulted in a delegation.
	Delegation
	// NoData indicates the lookup resulted in a NODATA.
	NoData
	// ServerFailure indicates a server failure during the lookup.
	ServerFailure
)

// Lookup looks up qname and qtype in the zone. When do is true DNSSEC records are included.
// Three sets of records are returned, one for the answer, one for authority  and one for the additional section.
func (z *Zone) Lookup(ctx context.Context, state request.Request, qname string, scion bool) ([]dns.RR, []dns.RR, []dns.RR, Result) {
	qtype := state.QType()
	do := false
	appendRRSIGs := true
	// If z is a secondary zone we might not have transferred it, meaning we have
	// all zone context setup, except the actual record. This means (for one thing) the apex
	// is empty and we don't have a SOA record.
	z.RLock()
	ap := z.Apex
	tr := z.Tree
	z.RUnlock()
	if ap.SOA == nil {
		return nil, nil, nil, ServerFailure
	}

	if qname == z.origin {
		switch qtype {
		case dns.TypeSOA:
			return ap.soa(appendRRSIGs), ap.ns(appendRRSIGs), nil, Success
		case dns.TypeNS:
			nsrrs := ap.ns(appendRRSIGs)
			glue := tr.Glue(nsrrs, appendRRSIGs, scion) // technically this isn't glue
			return nsrrs, nil, glue, Success
		}
	}

	var (
		found, shot    bool
		parts          string
		i              int
		elem, wildElem *tree.Elem
	)

	loop, _ := ctx.Value(dnsserver.LoopKey{}).(int)
	if loop > 8 {
		// We're back here for the 9th time; we have a loop and need to bail out.
		// Note the answer we're returning will be incomplete (more cnames to be followed) or
		// illegal (wildcard cname with multiple identical records). For now it's more important
		// to protect ourselves then to give the client a valid answer. We return with an error
		// to let the server handle what to do.
		return nil, nil, nil, ServerFailure
	}

	// Lookup:
	// * Per label from the right, look if it exists. We do this to find potential
	//   delegation records.
	// * If the per-label search finds nothing, we will look for the wildcard at the
	//   level. If found we keep it around. If we don't find the complete name we will
	//   use the wildcard.
	//
	// Main for-loop handles delegation and finding or not finding the qname.
	// If found we check if it is a CNAME/DNAME and do CNAME processing
	// We also check if we have type and do a nodata response.
	//
	// If not found, we check the potential wildcard, and use that for further processing.
	// If not found and no wildcard we will process this as an NXDOMAIN response.
	for {
		parts, shot = z.nameFromRight(qname, i)
		// We overshot the name, break and check if we previously found something.
		if shot {
			break
		}

		elem, found = tr.Search(parts)
		if !found {
			// Apex will always be found, when we are here we can search for a wildcard
			// and save the result of that search. So when nothing match, but we have a
			// wildcard we should expand the wildcard.

			wildcard := replaceWithAsteriskLabel(parts)
			if wild, found := tr.Search(wildcard); found {
				wildElem = wild
			}

			// Keep on searching, because maybe we hit an empty-non-terminal (which aren't
			// stored in the tree. Only when we have match the full qname (and possible wildcard
			// we can be confident that we didn't find anything.
			i++
			continue
		}

		// If we see DNAME records, we should return those.
		if dnamerrs := elem.Type(dns.TypeDNAME); dnamerrs != nil {
			// Only one DNAME is allowed per name. We just pick the first one to synthesize from.
			dname := dnamerrs[0]
			if cname := synthesizeCNAME(state.Name(), dname.(*dns.DNAME)); cname != nil {
				var (
					answer, ns, extra []dns.RR
					rcode             Result
				)

				// We don't need to chase CNAME chain for synthesized CNAME
				if qtype == dns.TypeCNAME {
					answer = []dns.RR{cname}
					ns = ap.ns(appendRRSIGs)
					extra = nil
					rcode = Success
				} else {
					ctx = context.WithValue(ctx, dnsserver.LoopKey{}, loop+1)
					answer, ns, extra, rcode = z.externalLookup(ctx, state, elem, []dns.RR{cname})
				}

				if appendRRSIGs {
					sigs := elem.Type(dns.TypeRRSIG)
					sigs = rrutil.SubTypeSignature(sigs, dns.TypeDNAME)
					dnamerrs = append(dnamerrs, sigs...)
					log.Warning("Appended RRSIGs")
				}

				// The relevant DNAME RR should be included in the answer section,
				// if the DNAME is being employed as a substitution instruction.
				answer = append(dnamerrs, answer...)
				return answer, ns, extra, rcode
			}
			// The domain name that owns a DNAME record is allowed to have other RR types
			// at that domain name, except those have restrictions on what they can coexist
			// with (e.g. another DNAME). So there is nothing special left here.
		}

		// If we see NS records, it means the name as been delegated, and we should return the delegation.
		if nsrrs := elem.Type(dns.TypeNS); nsrrs != nil {

			// If the query is specifically for DS and the qname matches the delegated name, we should
			// return the DS in the answer section and leave the rest empty, i.e. just continue the loop
			// and continue searching.
			if qtype == dns.TypeDS && elem.Name() == qname {
				i++
				continue
			}

			glue := tr.Glue(nsrrs, appendRRSIGs, scion)
			if appendRRSIGs {
				dss := typeFromElem(elem, dns.TypeDS, appendRRSIGs)
				nsrrs = append(nsrrs, dss...)

				// DSum and DSAProof
				log.Info("We entered NS processing")
				glue = z.rhineDelegationDSumAndDSAProof(glue, qname)
			}

			return nil, nsrrs, glue, Delegation
		}

		i++
	}

	// What does found and !shot mean - do we ever hit it?
	if found && !shot {
		return nil, nil, nil, ServerFailure
	}

	// Found entire name.
	if found && shot {

		if rrs := elem.Type(dns.TypeCNAME); len(rrs) > 0 && qtype != dns.TypeCNAME {
			ctx = context.WithValue(ctx, dnsserver.LoopKey{}, loop+1)
			return z.externalLookup(ctx, state, elem, rrs)
		}

		rrs := elem.Type(qtype)

		// NODATA
		if len(rrs) == 0 {
			ret := ap.soa(appendRRSIGs)
			if do {
				nsec := typeFromElem(elem, dns.TypeNSEC, do)
				ret = append(ret, nsec...)
			}
			return nil, ret, nil, NoData
		}

		// Additional section processing for MX, SRV. Check response and see if any of the names are in bailiwick -
		// if so add IP addresses to the additional section.
		additional := z.additionalProcessing(rrs, appendRRSIGs)
		log.Warning("Before append sigs")
		if appendRRSIGs {
			sigs := elem.Type(dns.TypeRRSIG)
			sigs = rrutil.SubTypeSignature(sigs, qtype)
			rrs = append(rrs, sigs...)
			log.Warning("Appended RRSIGs after additional")
		}
		log.Warning("QTYPE: ", qtype)
		if qtype == dns.TypeDNSKEY {
			n := dns.CompareDomainName(z.origin, qname)
			nsplit := dns.SplitDomainName(qname)
			var candidate string
			if len(nsplit)-n > 0 {
				candidate = dns.Fqdn(strings.Join(nsplit[len(nsplit)-n-1:], "."))
			} else {
				candidate = z.origin
			}
			log.Warning("DelegationProccessing")
			additional = z.rhineDelegationProcessing(additional, candidate)
		}
		return rrs, ap.ns(appendRRSIGs), additional, Success
	}

	// Haven't found the original name.

	// Found wildcard.
	if wildElem != nil {
		auth := ap.ns(appendRRSIGs)

		if rrs := wildElem.TypeForWildcard(dns.TypeCNAME, qname); len(rrs) > 0 && qtype != dns.TypeCNAME {
			ctx = context.WithValue(ctx, dnsserver.LoopKey{}, loop+1)
			return z.externalLookup(ctx, state, wildElem, rrs)
		}

		rrs := wildElem.TypeForWildcard(qtype, qname)

		// NODATA response.
		if len(rrs) == 0 {
			ret := ap.soa(appendRRSIGs)
			if do {
				nsec := typeFromElem(wildElem, dns.TypeNSEC, do)
				ret = append(ret, nsec...)
			}
			return nil, ret, nil, Success
		}

		if do {
			// An NSEC is needed to say no longer name exists under this wildcard.
			if deny, found := tr.Prev(qname); found {
				nsec := typeFromElem(deny, dns.TypeNSEC, appendRRSIGs)
				auth = append(auth, nsec...)
			}

			sigs := wildElem.TypeForWildcard(dns.TypeRRSIG, qname)
			sigs = rrutil.SubTypeSignature(sigs, qtype)
			rrs = append(rrs, sigs...)

		}
		return rrs, auth, nil, Success
	}

	rcode := NameError

	// Hacky way to get around empty-non-terminals. If a longer name does exist, but this qname, does not, it
	// must be an empty-non-terminal. If so, we do the proper NXDOMAIN handling, but set the rcode to be success.
	if x, found := tr.Next(qname); found {
		if dns.IsSubDomain(qname, x.Name()) {
			rcode = Success
		}
	}

	ret := ap.soa(appendRRSIGs)
	if do {
		deny, found := tr.Prev(qname)
		if !found {
			goto Out
		}
		nsec := typeFromElem(deny, dns.TypeNSEC, appendRRSIGs)
		ret = append(ret, nsec...)

		if rcode != NameError {
			goto Out
		}

		ce, found := z.ClosestEncloser(qname)

		// wildcard denial only for NXDOMAIN
		if found {
			// wildcard denial
			wildcard := "*." + ce.Name()
			if ss, found := tr.Prev(wildcard); found {
				// Only add this nsec if it is different than the one already added
				if ss.Name() != deny.Name() {
					nsec := typeFromElem(ss, dns.TypeNSEC, appendRRSIGs)
					ret = append(ret, nsec...)
				}
			}
		}

	}
Out:
	return nil, ret, nil, rcode
}

// typeFromElem returns the type tp from e and adds signatures (if they exist) and do is true.
func typeFromElem(elem *tree.Elem, tp uint16, do bool) []dns.RR {
	rrs := elem.Type(tp)
	if do {
		sigs := elem.Type(dns.TypeRRSIG)
		sigs = rrutil.SubTypeSignature(sigs, tp)
		rrs = append(rrs, sigs...)
	}
	return rrs
}

func (a Apex) soa(do bool) []dns.RR {
	if do {
		ret := append([]dns.RR{a.SOA}, a.SIGSOA...)
		return ret
	}
	return []dns.RR{a.SOA}
}

func (a Apex) ns(do bool) []dns.RR {
	if do {
		ret := append(a.NS, a.SIGNS...)
		return ret
	}
	return a.NS
}

// externalLookup adds signatures and tries to resolve CNAMEs that point to external names.
func (z *Zone) externalLookup(ctx context.Context, state request.Request, elem *tree.Elem, rrs []dns.RR) ([]dns.RR, []dns.RR, []dns.RR, Result) {

	qtype := state.QType()
	do := state.Do()

	if do {
		sigs := elem.Type(dns.TypeRRSIG)
		sigs = rrutil.SubTypeSignature(sigs, dns.TypeCNAME)
		rrs = append(rrs, sigs...)
	}

	targetName := rrs[0].(*dns.CNAME).Target
	elem, _ = z.Tree.Search(targetName)
	if elem == nil {
		lookupRRs, result := z.doLookup(ctx, state, targetName, qtype)
		rrs = append(rrs, lookupRRs...)
		return rrs, z.Apex.ns(do), nil, result
	}

	i := 0

Redo:
	cname := elem.Type(dns.TypeCNAME)
	if len(cname) > 0 {
		rrs = append(rrs, cname...)

		if do {
			sigs := elem.Type(dns.TypeRRSIG)
			sigs = rrutil.SubTypeSignature(sigs, dns.TypeCNAME)
			rrs = append(rrs, sigs...)
		}
		targetName := cname[0].(*dns.CNAME).Target
		elem, _ = z.Tree.Search(targetName)
		if elem == nil {
			lookupRRs, result := z.doLookup(ctx, state, targetName, qtype)
			rrs = append(rrs, lookupRRs...)
			return rrs, z.Apex.ns(do), nil, result
		}

		i++
		if i > 8 {
			return rrs, z.Apex.ns(do), nil, Success
		}

		goto Redo
	}

	targets := elem.Type(qtype)
	if len(targets) > 0 {
		rrs = append(rrs, targets...)

		if do {
			sigs := elem.Type(dns.TypeRRSIG)
			sigs = rrutil.SubTypeSignature(sigs, qtype)
			rrs = append(rrs, sigs...)
		}
	}

	return rrs, z.Apex.ns(do), nil, Success
}

func (z *Zone) doLookup(ctx context.Context, state request.Request, target string, qtype uint16) ([]dns.RR, Result) {
	m, e := z.Upstream.Lookup(ctx, state, target, qtype)
	if e != nil {
		return nil, ServerFailure
	}
	if m == nil {
		return nil, Success
	}
	if m.Rcode == dns.RcodeNameError {
		return m.Answer, NameError
	}
	if m.Rcode == dns.RcodeServerFailure {
		return m.Answer, ServerFailure
	}
	if m.Rcode == dns.RcodeSuccess && len(m.Answer) == 0 {
		return m.Answer, NoData
	}
	return m.Answer, Success
}

// additionalProcessing checks the current answer section and retrieves A or AAAA records
// (and possible SIGs) to need to be put in the additional section.
func (z *Zone) additionalProcessing(answer []dns.RR, do bool) (extra []dns.RR) {
	for _, rr := range answer {
		name := ""
		switch x := rr.(type) {
		case *dns.SRV:
			name = x.Target
		case *dns.MX:
			name = x.Mx
		}
		if len(name) == 0 || !dns.IsSubDomain(z.origin, name) {
			continue
		}

		elem, _ := z.Tree.Search(name)
		if elem == nil {
			continue
		}

		sigs := elem.Type(dns.TypeRRSIG)
		for _, addr := range []uint16{dns.TypeA, dns.TypeAAAA} {
			if a := elem.Type(addr); a != nil {
				extra = append(extra, a...)
				if do {
					sig := rrutil.SubTypeSignature(sigs, addr)
					extra = append(extra, sig...)
				}
			}
		}
	}

	return extra
}

func (z *Zone) rhineDelegationProcessing(rrs []dns.RR, childzone string) []dns.RR {
	log.Info("Entered Rhine rcert proc.")
	tr := z.Tree
	apex := z.origin
	if z.origin == "." {
		apex = ""
	}
	if rcert, ok := tr.Search("_rhinecert." + apex); ok {
		log.Info("Found RCert")
		Rcert := rcert.Type(dns.TypeTXT)
		rrs = append(rrs, Rcert...)
	}

	log.Info("Looks like :", rrs)

	return rrs
}

func (z *Zone) rhineDelegationDSumAndDSAProof(rrs []dns.RR, childzone string) []dns.RR {
	log.Info("Entered Rhine DSum and DSA proc.")
	tr := z.Tree
	apex := z.origin
	if z.origin == "." {
		apex = ""
	}
	// Search for dsum record
	if dsum, ok := tr.Search("_dsum." + apex); ok {
		log.Info("Found DSum")
		Dsum := dsum.Type(dns.TypeTXT)
		rrs = append(rrs, Dsum...)
	}
	// Search for DSA Proof record
	if dsaproof, ok := tr.Search("_dsaproof." + childzone); ok {
		log.Info("Found DSAProof for: ", childzone)
		Dsaproof := dsaproof.Type(dns.TypeTXT)
		rrs = append(rrs, Dsaproof...)
	} else {
		log.Info("Did not find DSAProof for: ", childzone)
	}
	/*
			if rSig, ok := tr.Search("_dsp." + apex); ok {
				log.Info("Found DSP")
				RhineSig := rSig.Type(dns.TypeTXT)
				rrs = append(rrs, RhineSig...)
			}

		if zoneAuth, ok := tr.Search(z.origin); ok {
			rrs = append(rrs, zoneAuth.Type(dns.TypeDNSKEY)...)

			sigs := zoneAuth.Type(dns.TypeRRSIG)
			sig := rrutil.SubTypeSignature(sigs, dns.TypeDNSKEY)
			rrs = append(rrs, sig...)
		}
	*/
	log.Info("Looks like :", rrs)

	return rrs
}
