package rhine

import (
	//"bytes"
	//"crypto/sha256"

	"errors"
	//"log"
	//"reflect"
	//"time"
	//"github.com/google/certificate-transparency-go/x509"
)

type Lreq struct {
	Logger string
	Nds    *Nds
	Atts   []*Confirm

	Signature []byte
}

func (p *Lreq) LreqToBytes() ([]byte, error) {
	bytes, err := SerializeCBOR(p)
	return bytes, err
}

func LreqFromBytes(in []byte) (*Lreq, error) {
	l := &Lreq{}
	err := DeserializeCBOR(in, l)
	return l, err
}

func (p *Lreq) SignLreq(privkey any) error {
	p.Signature = nil
	byt, err := p.LreqToBytes()
	if err != nil {
		return err
	}
	rsig := RhineSig{
		Data: byt,
	}
	err = rsig.Sign(privkey)
	if err != nil {
		return err
	}
	p.Signature = rsig.Signature

	return nil
}

func (p *Lreq) VerifyLreq(pubkey any) error {
	rsig := RhineSig{
		Signature: p.Signature,
	}
	p.Signature = nil
	byt, err := p.LreqToBytes()
	if err != nil {
		return err
	}
	rsig.Data = byt

	boolv := rsig.Verify(pubkey)

	if !boolv {
		return errors.New("Lreq has no valid signature")
	}
	return nil
}
