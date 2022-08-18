package pserver

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/rhine-team/RHINE-Prototype/offlineAuth/cbor"
	ps "github.com/rhine-team/RHINE-Prototype/offlineAuth/components/parentserver"
	"github.com/rhine-team/RHINE-Prototype/offlineAuth/rhine"
)

var ft1 *os.File
var measureT = true

type PServer struct {
	ps.UnimplementedParentServiceServer
	Zm *rhine.ZoneManager
}

func (s *PServer) InitDelegation(ctx context.Context, in *ps.InitDelegationRequest) (*ps.InitDelegationResponse, error) {
	res := &ps.InitDelegationResponse{}
	var measureTimes time.Time
	var elapsedTimes int64
	if measureT && ft1 == nil {
		ft1, _ = os.Create("ParentStats" + ".csv")
	}

	//log.Printf("InitDelegation service called %+v\n", *in)

	log.Printf("InitDelegation service called with RID: %s\n", rhine.EncodeBase64(in.Rid))

	// Verify the received csr
	_, psr, parentcert, err := s.Zm.VerifyChildCSR(in.Csr)
	if err != nil {
		return res, err
	}

	log.Println("CSR is valid")

	// Generate Acsr
	//psr := s.Zm.CreatePSR(csr)
	rsig := psr.GetRhineSig()
	//log.Printf("The following ACSR was constructed: %+v\n", rsig)

	log.Println("DLGT_APPROVAL created.")

	res = &ps.InitDelegationResponse{
		Approvalcommit: &ps.RhineSig{
			Data: rsig.Data,
			Sig:  rsig.Signature,
		},
		Rcertp: parentcert,
	}
	//log.Printf("We send response: %+v\n", res)
	//log.Printf("Delegation successfull: InitDelegationResponse sent for RID : %+v ", in.Rid)
	log.Printf("Delegation successfull: InitDelegationResponse sent for RID : %s\n", rhine.EncodeBase64(in.Rid))

	if measureT {
		elapsedTimes = elapsedTimes + time.Since(measureTimes).Microseconds()
		ft1.WriteString(fmt.Sprintf("%d\n", elapsedTimes))
	}
	return res, nil
}
