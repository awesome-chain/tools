package main

import (
	"awesome-algo/crypto"
	"encoding/hex"
	"github.com/magiconair/properties/assert"
	"testing"
)

func TestMulti(t *testing.T){
	msg := []byte("hello world")
	pub1, _, _ := crypto.ED25519GenerateKey()
	pub2, prv2, _ := crypto.ED25519GenerateKey()
	pub3, prv3, _ := crypto.ED25519GenerateKey()
	//_, prv4, _ := crypto.ED25519GenerateKey()
	sigs := &crypto.MultiSignatures{
		Version:1,
		Threshold:2,
		SubSignatures:make([]*crypto.MultiSubSig, 0),
	}
	subSig1 := &crypto.MultiSubSig{
		Key:pub1,
	}
	subSig2 := &crypto.MultiSubSig{
		Key:pub2,
	}
	subSig3 := &crypto.MultiSubSig{
		Key:pub3,
	}
	sigs.SubSignatures = append(sigs.SubSignatures, subSig1)
	sigs.SubSignatures = append(sigs.SubSignatures, subSig2)
	sigs.SubSignatures = append(sigs.SubSignatures, subSig3)
	pks := make([]crypto.PublicKey, 0)
	pks = append(pks, pub1, pub2, pub3)
	addr, err := crypto.MultiSigAddrGen(1, 2, pks)
	if err != nil{
		t.Error(err)
		return
	}
	t.Logf("multi sign address is: [0x%s]", hex.EncodeToString(addr[:]))
	err = crypto.MultiSignWithOneKey(sigs, msg, addr, 1, 2, pks, prv2)
	if err != nil{
		t.Error(err)
		return
	}
	err = crypto.MultiSignWithOneKey(sigs, msg, addr, 1, 2, pks, prv3)
	if err != nil{
		t.Error(err)
		return
	}
	ok, err := crypto.MultiSignVerify(msg, addr, sigs)
	if err != nil{
		t.Error(err)
		return
	}
	assert.Equal(t, ok, true, "multi sign verify failed")
}
