package aggserver

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/certificate-transparency-go/x509"
	_ "github.com/rhine-team/RHINE-Prototype/offlineAuth/cbor"
	pf "github.com/rhine-team/RHINE-Prototype/offlineAuth/components/aggregator"
	"github.com/rhine-team/RHINE-Prototype/offlineAuth/rhine"
)

var ft1 *os.File
var measureT = false

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
	if measureT && ft1 == nil {
		ft1, _ = os.Create("AggTimeStats" + ".csv")
	}
	var measureTimes time.Time
	var elapsedTimes int64
	if measureT {
		elapsedTimes = 0
		measureTimes = time.Now()
	}
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

	if measureT {
		elapsedTimes = elapsedTimes + time.Since(measureTimes).Microseconds()
		ft1.WriteString(fmt.Sprintf("%d\n", elapsedTimes))
		ft1.Sync()
	}

	return res, nil
}
