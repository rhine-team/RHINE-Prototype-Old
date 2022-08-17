package caserver

import (
	"context"
	"errors"
	"log"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/google/certificate-transparency-go/x509"
	_ "github.com/rhine-team/RHINE-Prototype/offlineAuth/cbor"
	pf "github.com/rhine-team/RHINE-Prototype/offlineAuth/components/ca"
	"github.com/rhine-team/RHINE-Prototype/offlineAuth/rhine"

	agg "github.com/rhine-team/RHINE-Prototype/offlineAuth/components/aggregator"
	logp "github.com/rhine-team/RHINE-Prototype/offlineAuth/components/log"
)

// Set timeout
var timeout = time.Second * 30
var count = 0

type SCTandLConf struct {
	sct        []byte
	lconf      rhine.Confirm
	lconfbytes []byte
}

type CAServer struct {
	pf.UnimplementedCAServiceServer
	Ca *rhine.Ca
}

func (s *CAServer) SubmitNewDelegCA(ctx context.Context, in *pf.SubmitNewDelegCARequest) (*pf.SubmitNewDelegCAResponse, error) {
	res := &pf.SubmitNewDelegCAResponse{}

	log.Printf("Received NewDeleg from Child with RID %s", rhine.EncodeBase64(in.Rid))

	acsr := &rhine.RhineSig{
		Data:      in.Acsr.Data,
		Signature: in.Acsr.Sig,
	}

	rcertp, errcert := x509.ParseCertificate(in.Rcertp)
	if errcert != nil {
		// Certificate parsing failure
		log.Println("Failed to parse RCertParent")
		return res, errcert
	}

	// Run initial verification steps
	acc, errverif, psr := s.Ca.VerifyNewDelegationRequest(rcertp, acsr)
	if errverif != nil {
		log.Println("Error during inital Checks!")
		return res, errverif
	}
	if !acc {
		log.Println("Initial Checks failed!")
		return res, errors.New("Initial Delegation checked and rejected by CA")
	}

	log.Println("Initial verification steps passed, procceding with DSP")

	// Now we run DSProofRet to get dsps

	// Make dspRequest
	dspRequest := &logp.DSProofRetRequest{Childzone: psr.ChildZone, Parentzone: psr.ParentZone}

	clientsLogger := make([]logp.LogServiceClient, len(psr.GetLogs()))
	// Make connections for all designated loggers

	// Use error group to fail goroutines if network issue or dsp does not validate
	errGroup := new(errgroup.Group)

	for i, logger := range psr.GetLogs() {
		i := i
		logger := logger

		// Create connections and clients, remember to reuse later
		conn := rhine.GetGRPCConn(logger)
		defer conn.Close()
		clientsLogger[i] = logp.NewLogServiceClient(conn)

		errGroup.Go(func() error {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			r, err := clientsLogger[i].DSProofRet(ctx, dspRequest)
			if err != nil {
				log.Printf("No good response: %v", err)
				return err
			}

			// Parse the response
			dsp, errdeser := rhine.DeserializeStructure[rhine.Dsp](r.DSPBytes)
			if errdeser != nil {
				log.Printf("Error while deserializing dsp: %v", errdeser)
				return errdeser
			}

			//log.Printf("Our DSP Response from the log %+v", r)
			//log.Printf("Our DSP we got from the log %+v", dsp)

			// Check validity of dsp
			// Check if proof is correct
			// Check if pcert matches dsp
			// Check ALC and ALP compatibility
			if !(&dsp).Verify(s.Ca.LogMap[logger].Pubkey, psr.ChildZone, rcertp, psr.GetAlFromCSR()) {
				log.Println("Verification of dsp failed")
				//noFailureChannel <- false
				return errors.New("Verification of DSP and check against it failed!")
				//return res, errors.New("Verification of DSP and check against it failed!")
			}

			log.Println("DSP verified with success. For logger: ", logger)
			return nil
		})

	}

	log.Println("All DSProofs fine")

	// Create PreRC and NDS
	preRC := s.Ca.CreatePoisonedCert(psr)
	nds, errnds := s.Ca.CreateNDS(psr, preRC)
	if errnds != nil {
		return res, errnds
	}
	log.Printf("Constructed NDS looks like this: %+v", nds)

	// Reuse earlier connection

	ndsBytes, ndsBerr := nds.NdsToBytes()
	if ndsBerr != nil {
		return res, ndsBerr
	}

	// Construct log ACSR
	acsrLog := &logp.RhineSig{
		Data: in.Acsr.Data,
		Sig:  in.Acsr.Sig,
	}

	// Wait for DSProof goroutines
	if err := errGroup.Wait(); err != nil {
		return res, err
	}
	log.Println("All DSProof routines return valid")

	// Use error group to fail goroutines if network issue or dsp does not validate
	errGroup = new(errgroup.Group)

	LogWitnessList := make([]rhine.Lwit, len(psr.GetLogs()))
	logWitnessReturns := make(chan rhine.Lwit, len(psr.GetLogs()))
	for i, _ := range psr.GetLogs() {
		i := i
		errGroup.Go(func() error {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			rDemandLog, errDL := clientsLogger[i].DemandLogging(ctx, &logp.DemandLoggingRequest{Acsr: acsrLog, ParentRcert: in.Rcertp, ChildPreRC: preRC.Raw, Nds: ndsBytes, Rid: in.Rid})
			if errDL != nil {
				log.Printf("No good response from log for DemandLogging: %v", errDL)
				return errDL
			}

			//log.Printf("Received res for Demand Logging %+v ", rDemandLog)
			log.Printf("Received response for DemandLogging ")

			// Collect Lwits
			var newLwit rhine.Lwit
			newLwit = rhine.Lwit{
				Rsig: &rhine.RhineSig{
					Data:      rDemandLog.LogWitness.Data,
					Signature: rDemandLog.LogWitness.Sig,
				},
				NdsBytes: rDemandLog.LogWitness.NdsHash,
				Log:      &rhine.Log{Name: rDemandLog.LogWitness.Log},
				LogList:  rDemandLog.LogWitness.DesignatedLogs,
			}
			//LogWitnessList = append(LogWitnessList, newLwit)
			logWitnessReturns <- newLwit
			return nil
		})
	}

	// Wait for LogWitness responses
	if err := errGroup.Wait(); err != nil {
		return res, err
	}

	// Collect the Lwits from the routines
	for i := range psr.GetLogs() {
		l := <-logWitnessReturns
		LogWitnessList[i] = l
	}

	// Step 11: Verify Lwits
	if !rhine.VerifyLwitSlice(LogWitnessList, s.Ca.LogMap) {
		return res, errors.New("One of the LogWitness failed verification!")
	}
	// Match Lwit and NDS
	if !nds.MatchWithLwits(LogWitnessList) {
		return res, errors.New("Lwit did not match with NDS")
	}

	log.Println("LOG_WITNESS list verified and matched with NDS")

	// Construct message for Aggregator containing list of log witnesses and NDS
	var lwitAggList []*agg.Lwit
	for _, lwi := range LogWitnessList {
		lw := &agg.Lwit{
			DesignatedLogs: lwi.LogList,
			Log:            lwi.Log.Name,
			NdsHash:        lwi.NdsBytes,
			Data:           lwi.Rsig.Data,
			Sig:            lwi.Rsig.Signature,
		}

		lwitAggList = append(lwitAggList, lw)
	}

	aggMsg := &agg.SubmitNDSRequest{
		Nds:           ndsBytes,
		Lwits:         lwitAggList,
		Rid:           in.Rid,
		Acsrpayload:   acsr.Data,
		Acsrsignature: acsr.Signature,
		Rcertp:        rcertp.Raw,
	}

	// Send all allgregs the log witnesses
	// Use error group to fail goroutines if network issue or dsp does not validate
	errGroup = new(errgroup.Group)

	clientsAggreg := make([]agg.AggServiceClient, len(nds.Nds.Agg))
	aggConfirmList := make([]rhine.Confirm, len(nds.Nds.Agg))
	aggConfirmListBytes := make([][]byte, len(nds.Nds.Agg))
	aggConfirmReturns := make(chan rhine.Confirm, len(nds.Nds.Agg))
	aggConfirmBytesReturns := make(chan []byte, len(nds.Nds.Agg))
	// Make connections for all designated aggregators
	for i, aggregat := range nds.Nds.Agg {
		i := i
		aggregat := aggregat
		connAgg := rhine.GetGRPCConn(aggregat)
		defer connAgg.Close()
		cAgg := agg.NewAggServiceClient(connAgg)
		clientsAggreg[i] = cAgg
		errGroup.Go(func() error {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			rAgg, err := cAgg.SubmitNDS(ctx, aggMsg)
			if err != nil {
				return err
			}

			log.Println("Response received by aggregator for SubmitNDS")

			// Collect received confirms

			aggConf, errTranspConf := rhine.TransportBytesToConfirm(rAgg.Acfmg)
			if errTranspConf != nil {
				log.Println("Transport bytes to confirm failed: ", errTranspConf)
				return errTranspConf
			}

			aggConfirmReturns <- *aggConf
			aggConfirmBytesReturns <- rAgg.Acfmg
			//aggConfirmList = append(aggConfirmList, *aggConf)
			//aggConfirmListBytes = append(aggConfirmListBytes, rAgg.Acfmg)
			return nil
		})
	}

	// Wait for aggregator responses
	if err := errGroup.Wait(); err != nil {
		return res, err
	}

	// Collect the Lwits from the routines
	for i := range nds.Nds.Agg {
		aggConfirmList[i] = <-aggConfirmReturns
		aggConfirmListBytes[i] = <-aggConfirmBytesReturns
	}

	// Check Signatures on Agg_confirms and
	// Check match between nds and dsum

	// Check match of confirms with nds
	if !nds.MatchWithConfirm(aggConfirmList) {
		return res, errors.New("One of the AggConfirms did not match the NDS")
	}
	// Check if Confirms are correctly signed
	if !rhine.VerifyAggConfirmSlice(aggConfirmList, s.Ca.AggMap) {
		return res, errors.New("An AggConfirm was not correctly signed")
	}

	log.Println("CA: All AggConfirms checked with success.")

	// Communicate back to the log and hand in the AggConfirms
	// Connection already established :

	// Collect LogConfirms
	logConfirmList := make([]rhine.Confirm, len(psr.GetLogs()))
	logConfirmListBytes := make([][]byte, len(psr.GetLogs()))
	SCTS := make([][]byte, len(psr.GetLogs()))
	pubKeyInOrder := []any{}
	sctAndLConf := make(chan SCTandLConf, len(psr.GetLogs()))
	for i, _ := range psr.GetLogs() {
		i := i
		errGroup.Go(func() error {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			rSubAcfm, errSubAcfm := clientsLogger[i].SubmitACFM(ctx, &logp.SubmitACFMRequest{Acfms: aggConfirmListBytes, Rid: in.Rid})
			if errSubAcfm != nil {
				return errSubAcfm
			}

			logConf, errTranspConfL := rhine.TransportBytesToConfirm(rSubAcfm.Lcfm)
			if errTranspConfL != nil {
				return errTranspConfL
			}

			sctnlconf := SCTandLConf{
				sct:        rSubAcfm.SCT,
				lconf:      *logConf,
				lconfbytes: rSubAcfm.Lcfm,
			}
			sctAndLConf <- sctnlconf
			return nil
		})
	}

	// Wait for loggers responses
	if err := errGroup.Wait(); err != nil {
		return res, err
	}

	// Collect the SCTS and Confirms from the routines
	for i := range psr.GetLogs() {
		snl := <-sctAndLConf
		// Collect Confirms
		logConfirmList[i] = snl.lconf
		logConfirmListBytes[i] = snl.lconfbytes
		SCTS[i] = snl.sct
		pubKeyInOrder = append(pubKeyInOrder, s.Ca.LogMap[snl.lconf.EntityName].Pubkey)
	}

	// Check if LogConfirms are correctly signed
	if !rhine.VerifyLogConfirmSlice(logConfirmList, s.Ca.LogMap) {
		return res, errors.New("A LogConfirm was not correctly signed")
	}
	log.Println("CA: All LogConfirms checked and valid")

	// Issue Cert!
	chilcert := s.Ca.IssueRHINECert(preRC, psr, SCTS)

	// Check SCT
	// We check SCT after embedding of SCTs, to reuse functions
	if err := rhine.VerifyEmbeddedSCTs(chilcert, s.Ca.CACertificate, pubKeyInOrder); err != nil {
		log.Println("CA: Verification of atleast one SCT failed")
		return res, err
	}
	/*
		if err := rhine.VerifyEmbeddedSCTs(chilcert, s.Ca.CACertificate, s.Ca.LogMap[s.Ca.LogList[0]].Pubkey); err != nil {
			log.Println("CA: Verification of atleast one SCT failed")
			return res, err
		}
	*/
	//log.Println(chilcert)

	res = &pf.SubmitNewDelegCAResponse{
		Rcertc: chilcert.Raw,
		Lcfms:  logConfirmListBytes,
		Rid:    in.Rid,
	}

	count = count + 1
	log.Println("NUMBER ISSUED ", count)
	return res, nil

}
