package rhine

import (
	"crypto/sha256"
	"errors"
	"time"
)

type DSumNR struct {
	Dacc DAcc
	Alv  AuthorityLevel
	Cert []byte // hash of TBSRc_zone
	Exp  time.Time

	LoggerList []string
	Signatures [][]byte
}

func (dsa *DSA) GetDSumNR(ll []string) *DSumNR {
	dnr := &DSumNR{
		Dacc:       dsa.GetDAcc(),
		Alv:        dsa.Alv,
		Cert:       dsa.Cert,
		Exp:        dsa.Exp,
		LoggerList: ll,
		Signatures: make([][]byte, len(ll), len(ll)),
	}
	return dnr
}

func (d *DSumNR) SignOne(loggername string, privkey any) error {
	byt, err := d.GetDSumNRToBytes()
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

	for i, v := range d.LoggerList {
		if v == loggername {
			d.Signatures[i] = rsig.Signature
		}
	}

	return nil
}

func (d *DSumNR) VerifyOne(loggername string, pubkey any) error {
	var ind int
	for i, v := range d.LoggerList {
		if v == loggername {
			ind = i
		}
	}

	byt, err := d.GetDSumNRToBytes()
	if err != nil {
		return err
	}
	rsig := RhineSig{
		Data:      byt,
		Signature: d.Signatures[ind],
	}

	if !rsig.Verify(pubkey) {
		return errors.New("DSumNR failed verification of signature for: " + loggername)
	}
	return nil
}

func (d *DSumNR) GetDSumNRToBytes() ([]byte, error) {
	hasher := sha256.New()

	hasher.Write([]byte(d.Dacc.Zone))
	hasher.Write(d.Dacc.Roothash)
	hasher.Write([]byte{byte(d.Alv)})
	hasher.Write(d.Cert)

	// expiration time
	if timeBinary, err := d.Exp.MarshalBinary(); err != nil {
		return nil, err
	} else {
		hasher.Write(timeBinary)
	}
	// Add LoggerList
	for _, logger := range d.LoggerList {
		hasher.Write([]byte(logger))
	}

	return hasher.Sum(nil), nil
}

func (ds *DSumNR) SerializeDSumNRToString() (string, error) {
	bytes, err := SerializeCBOR(ds)
	if err != nil {
		return "", err
	}
	var res string
	res = EncodeBase64(bytes)
	return res, nil
}

func DeserializeDSumNRFromString(in string) (*DSumNR, error) {
	ds := &DSumNR{}
	bytes, errdec := DecodeBase64(in)
	if errdec != nil {
		return ds, errdec
	}
	err := DeserializeCBOR(bytes, ds)
	return ds, err
}