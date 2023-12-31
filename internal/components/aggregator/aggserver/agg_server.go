package aggserver

import (
	"bytes"
	"context"
	"errors"

	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/google/certificate-transparency-go/x509"
	_ "github.com/rhine-team/RHINE-Prototype/internal/cbor"
	pf "github.com/rhine-team/RHINE-Prototype/internal/components/aggregator"
	"github.com/rhine-team/RHINE-Prototype/pkg/rhine"
)

/*
var ft1 *os.File
var measureT = false
var timeout = time.Scond * 7200
var startTime time.Time
var started int
*/

var timeout = time.Second * 7200
var startTime time.Time
var started int

type AggServer struct {
	pf.UnimplementedAggServiceServer
	AggManager *rhine.AggManager
}

func (s *AggServer) DSRetrieval(ctx context.Context, in *pf.RetrieveDSALogRequest) (*pf.RetrieveDSALogResponse, error) {
	res := &pf.RetrieveDSALogResponse{}

	dsaBytes, dsaSigs, err := s.AggManager.Dsalog.DSRetrieve(in.RequestedZones, s.AggManager.GetPrivKey(), s.AggManager.DB)
	if err != nil {
		return res, err
	}

	res = &pf.RetrieveDSALogResponse{
		DSAPayload:    dsaBytes,
		DSASignatures: dsaSigs,
	}
	return res, nil

}

func (s *AggServer) DSProofRet(ctx context.Context, in *pf.DSProofRetRequest) (*pf.DSProofRetResponse, error) {
	res := &pf.DSProofRetResponse{}

	log.Printf("Received a DSProofRet request: %+v", in)

	dsp, dsperr := s.AggManager.DSProof(in.Parentzone, in.Childzone)
	if dsperr != nil {
		return res, dsperr
	}

	// Encode and send
	//dspseri, err := rhine.SerializeStructure[rhine.Dsp](dsp)
	dspseri, err := rhine.SerializeCBOR(dsp)
	//log.Printf("DSP, serialized: %+v", dsp)

	if err != nil {
		return res, err
	}

	res = &pf.DSProofRetResponse{DSPBytes: dspseri}
	return res, nil

}

func (s *AggServer) SubmitNDS(ctx context.Context, in *pf.SubmitNDSRequest) (*pf.SubmitNDSResponse, error) {

	res := &pf.SubmitNDSResponse{}

	log.Printf("SubmitNDS service called with RID: %s\n", rhine.EncodeBase64(in.Rid))
	//log.Printf("Received request %+v", in)

	// Construct rhine representation of Lwits
	var LogWitnessList []rhine.Lwit
	for _, lwit := range in.Lwits {
		newLwit := rhine.Lwit{
			Signature: lwit.Sig,
			NdsBytes:  lwit.NdsHash,
			Log:       &rhine.Log{Name: lwit.Log},
			LogList:   lwit.DesignatedLogs,
		}
		LogWitnessList = append(LogWitnessList, newLwit)
	}

	// Parse Pcert
	pcert, errpcertparse := x509.ParseCertificate(in.Rcertp)
	if errpcertparse != nil {
		return res, errpcertparse
	}

	// Parse in RSig
	psr := rhine.CreatePsr(pcert, &rhine.RhineSig{Data: in.Acsrpayload, Signature: in.Acsrsignature})

	// Check that ACSR was signed by Parent and
	// Check that the csr is signed by the Child
	// And check that child and parent are what they say
	if errpsr := psr.Verify(s.AggManager.CertPool); errpsr != nil {
		return res, errpsr
	}

	// Parse NDS
	nds, errNDS := rhine.BytesToNds(in.Nds)
	if errNDS != nil {
		return res, errNDS
	}

	// Check NDS against CSR
	if !nds.CheckAgainstCSR(psr.GetCsr()) {
		log.Printf("Failed check of NDS against CSR: %+v ", nds)
		return res, errors.New("Failed check of NDS against CSR at aggregator")
	}

	// Check Correct Signature on NDS
	if err := nds.VerifyNDS(s.AggManager.Ca.Pubkey); err != nil {
		return res, err
	}

	log.Println("NDS is correctly signed.")

	// Step 13 Checks
	if !rhine.VerifyLwitSlice(LogWitnessList, s.AggManager.LogMap) {
		return res, errors.New("Aggregator: One of the LogWitness failed verification!")
	}

	//log.Println("Log witnesses are valid")

	// Match Lwit and NDS
	if !nds.MatchWithLwits(LogWitnessList) {
		return res, errors.New("Aggregator: Lwit did not match with NDS")
	}

	log.Println("Log witness list matches NDS")

	acfm, errAccNDS := s.AggManager.AcceptNDSAndStore(nds)
	if errAccNDS != nil {
		return res, errAccNDS
	}

	log.Println("NDS Submission has been accepted.")

	acfmBytes, erracfm := acfm.ConfirmToTransportBytes()
	if erracfm != nil {
		return res, erracfm
	}

	res = &pf.SubmitNDSResponse{
		Acfmg: acfmBytes,
		Rid:   in.Rid,
	}

	log.Printf("SubmitNDSResponse sent for RID: %s\n", rhine.EncodeBase64(in.Rid))

	return res, nil
}

func (s *AggServer) PreLogging(ctx context.Context, in *pf.PreLoggingRequest) (*pf.PreLoggingResponse, error) {

	res := &pf.PreLoggingResponse{}

	//log.Printf("Logging service called with RID: %s\n", rhine.EncodeBase64(in.Rid))
	//log.Printf("Received request %+v", in)

	prl, err := rhine.PrlFromBytes(in.Prl)
	if err != nil {
		return res, err
	}

	errver := prl.VerifyPrl(s.AggManager.Ca.Pubkey)
	if errver != nil {
		log.Println("Failed Verify prl")
		return res, errver
	}

	preRC, _ := x509.ParseCertificate(prl.Precert)
	nds, errnds := s.AggManager.CreateNDS(prl.Psr, preRC)
	if errnds != nil {
		return res, errnds
	}

	// Check psr
	errpsr := prl.Psr.Verify(s.AggManager.CertPool)
	if errpsr != nil {
		return res, errpsr
	}

	// Check input against DSP from local DSA
	dsp, errdsp := s.AggManager.DSProof(prl.Psr.ParentZone, prl.Psr.ChildZone)
	if errdsp != nil {
		return res, errdsp
	}

	// Check validity of dsp
	// Check if proof is correct
	// Check if pcert matches dsp
	// Check ALC and ALP compatibility
	if !(&dsp).Verify(s.AggManager.PubKey, prl.Psr.ChildZone, prl.Psr.Pcert, prl.Psr.GetAlFromCSR()) {
		log.Println("Verification of dsp failed")
		return res, errors.New("Verification of DSP failed / Checks against it failed")
	}

	log.Println("Local DSP valid, proof is correct, corresponds to ParentCert")

	att, errconf := rhine.CreateConfirm(0, nds, s.AggManager.Agg.Name, rhine.DSum{}, s.AggManager.GetPrivKey())
	if errconf != nil {
		return res, errconf
	}
	attbyte, errbyt := (att).ConfirmToTransportBytes()
	if errbyt != nil {
		return res, errbyt
	}

	res = &pf.PreLoggingResponse{
		Att: attbyte,
	}

	//log.Printf("SubmitNDSResponse sent for RID: %s\n", rhine.EncodeBase64(in.Rid))

	return res, nil
}

func (s *AggServer) Logging(ctx context.Context, in *pf.LoggingRequest) (*pf.LoggingResponse, error) {

	res := &pf.LoggingResponse{}

	//log.Printf("Logging service called with RID: %s\n", rhine.EncodeBase64(in.Rid))
	//log.Printf("Received request %+v", in)

	lreq, err := rhine.LreqFromBytes(in.Lreq)
	if err != nil {
		return res, err
	}

	errlr := lreq.VerifyLreq(s.AggManager.Ca.Pubkey)
	if err != nil {
		return res, errlr
	}

	// Verify atts
	if !rhine.VerifyAggConfirmSlicePtr(lreq.Atts, s.AggManager.AggMap) {
		log.Println("Failed Att verify")
		return res, errors.New("Att verification fail")
	}

	att, errconf := rhine.CreateConfirm(0, lreq.Nds, s.AggManager.Agg.Name, rhine.DSum{}, s.AggManager.GetPrivKey())
	if errconf != nil {
		return res, errconf
	}
	attbyte, errbyt := (att).ConfirmToTransportBytes()
	if errbyt != nil {
		return res, errbyt
	}

	res = &pf.LoggingResponse{
		LogConf: attbyte,
	}

	//log.Printf("SubmitNDSResponse sent for RID: %s\n", rhine.EncodeBase64(in.Rid))

	return res, nil
}

func (s *AggServer) StartLogres(ctx context.Context, in *pf.StartLogresRequest) (*pf.StartLogresResponse, error) {
	res := &pf.StartLogresResponse{}

	lri := []*rhine.Lreq{}
	//count := 0

	nms := &rhine.LogresMsg{
		Lr:     lri,
		Entity: s.AggManager.Agg.Name,
	}
	nms.Sign(s.AggManager.GetPrivKey())
	byt, _ := nms.ToBytes()

	// Send to all passiv nodes
	clientsLogger := make([]pf.AggServiceClient, len(s.AggManager.AggList))
	// Make connections for all designated loggers

	log.Println("Received request to Start")
	logresreq := &pf.LogresValueRequest{Msg: byt}
	var wg sync.WaitGroup
	wg.Add(len(clientsLogger))

	for i, logger := range s.AggManager.AggList {
		defer wg.Done()
		if logger == s.AggManager.Agg.Name {
			continue
		}
		i := i
		logger := logger

		// Create connections and clients, remember to reuse later

		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			conn := rhine.GetGRPCConn(logger)
			defer conn.Close()
			clientsLogger[i] = pf.NewAggServiceClient(conn)

			_, err := clientsLogger[i].LogresValue(ctx, logresreq)
			if err != nil {
				log.Printf("No good response: %v", err)
			}

		}()

	}
	wg.Wait()

	return res, nil

}

func (s *AggServer) LogresValue(ctx context.Context, in *pf.LogresValueRequest) (*pf.LogresValueResponse, error) {
	if started == 0 {
		startTime = time.Now()
		started = started + 1
	}

	res := &pf.LogresValueResponse{}

	msg, _ := rhine.LogresMsgFromBytes(in.Msg)

	if s.AggManager.Agg.Name == msg.Entity {
		return res, nil
	}

	f := s.AggManager.F

	//logresdatakey := "test" //msg.Entity

	log.Println("Received Logres Value")
	var round int
	// Check round
	r, ok := s.AggManager.LogresRound.Get("Round" + msg.Entity)
	if ok {
		round = r
	} else {
		round = 1
	}

	channel, oklogres := s.AggManager.LogresData.Get(msg.Entity)
	log.Println("Channel data found: ", oklogres)
	channel <- msg
	log.Println("After channel")

	// Check if this round is finished
	log.Println("Channel", len(channel))
	if len(channel) == len(s.AggManager.AggList)-2 || round == 1 {
		log.Println("Full channel in round", round)
		valid_input := []*rhine.Lreq{}

		// Logres Checking
		// Empty channel
		for len(channel) > 0 {
			logresmsg := <-channel
			// Verify the message
			reserr := logresmsg.Verify(s.AggManager.AggMap[logresmsg.Entity])
			log.Println("Res", reserr)
			for ol, lreq := range logresmsg.Lr {
				resveri := lreq.VerifyLreq(s.AggManager.AggMap[lreq.Logger])
				log.Println("Res", resveri)
				// Verify atts
				boolres := rhine.VerifyAggConfirmSlicePtr(lreq.Atts, s.AggManager.AggMap)
				log.Println("Res", boolres)

				if round <= 1 {
					valid_input = append(valid_input, lreq)
				} else if ol <= 100000/(round+2) {
					valid_input = append(valid_input, lreq)
				}
			}

		}

		// Get witnessed
		//alllreqsseen, oklo := s.AggManager.LogresCurrentSeen.Get(msg.Entity)
		oklo := true
		var w []*rhine.Lreq

		for _, ol := range valid_input {
			res := bytes.Compare(ol.Nds.Nds.TbsCert, ol.Atts[0].NdsHashBytes)
			log.Println("Comp", res)
		}

		if !oklo {
			w = []*rhine.Lreq{}
			w = valid_input
		} else {
			w = []*rhine.Lreq{}
		}
		log.Println("W", w)
		round += 1

		// Sign seen stuff
		newmsg := &rhine.LogresMsg{
			Lr: valid_input,
			//Entity: s.AggManager.Agg.Name,
			Entity: msg.Entity,
		}

		newmsg.Sign(s.AggManager.GetPrivKey())
		bytm, _ := newmsg.ToBytes()

		// Set seen
		//s.AggManager.LogresCurrentSeen.Set(msg.Entity, w)

		// Advance round
		s.AggManager.LogresRound.Set("Round"+msg.Entity, round)
		// Send out values
		// Send to all passiv nodes
		clientsLogger := make([]pf.AggServiceClient, len(s.AggManager.AggList))
		// Make connections for all designated loggers

		logresreq := &pf.LogresValueRequest{Msg: bytm}

		log.Println("====THIS IS ROUND=== ", round)
		if round >= f+1 {
			// Break off protocol
			elapsed := time.Since(startTime)
			ft, _ := os.Create("EndingTime" + ".csv")
			ft.WriteString(fmt.Sprintf("%d\n", elapsed.Milliseconds()))
			ft.Sync()
			fmt.Println("We ran all rounds with success! :", msg.Entity)
			log.Println("We ran all rounds with success!")

			return res, nil
		}

		//var wg sync.WaitGroup
		//wg.Add(len(clientsLogger))

		for i, logger := range s.AggManager.AggList {
			if logger == s.AggManager.Agg.Name || logger == msg.Entity {
				continue
			}
			i := i
			logger := logger

			go func() {
				// Create connections and clients, remember to reuse later
				conn := rhine.GetGRPCConn(logger)
				defer conn.Close()
				clientsLogger[i] = pf.NewAggServiceClient(conn)
				//defer wg.Done()
				ctx, _ := context.WithTimeout(context.Background(), timeout) //cancel
				//defer cancel()
				//log.Println("Cancel", cancel)

				_, err := clientsLogger[i].LogresValue(ctx, logresreq)
				if err != nil {
					log.Printf("No good response: %v", err)
				}

			}()

		}
		time.Sleep(1 * time.Second)
		//wg.Wait()
	}

	return res, nil

}
