package main

import (
	"awesome-algo/crypto"
	"encoding/hex"
	"github.com/magiconair/properties/assert"
	"strconv"
	"testing"
)

type PartKey struct {
	RoundID uint64
	MasterKey [32]byte
	PubKey [32]byte
	PrvKey [64]byte
	Sig [64]byte
}

func TestKeyPair(t *testing.T) {
	var pubKey [32]byte
	var prvKey [64]byte
	pubKey, prvKey, err := crypto.ED25519GenerateKey()
	if err != nil {
		t.Error(err)
		return
	}
	t.Logf("public key is: [0x%s]", hex.EncodeToString(pubKey[:]))
	t.Logf("private key is: [0x%s]", hex.EncodeToString(prvKey[:]))
	t.Logf("address is: [0x%s]", hex.EncodeToString(pubKey[:]))
	msg := []byte("hello world")
	sign := crypto.ED25519Sign(prvKey, msg)
	valid := crypto.ED25519Verify(pubKey, msg, sign)
	if !valid{
		t.Error("check sign failed")
		return
	}
	t.Logf("sign msg [%s], checked passed with referred public key", msg)
	pubKey0 := crypto.RetrievePubkey(prvKey)
	assert.Equal(t, pubKey0, pubKey, "retrieve public key from private key not matched")
}

func TestKeyPairWithVrfKey(t *testing.T) {
	var pubKey [32]uint8
	var prvKey [64]uint8
	pubKey, prvKey = crypto.VRFKeygen()
	t.Logf("public key is: [0x%s]", hex.EncodeToString(pubKey[:]))
	t.Logf("private key is: [0x%s]", hex.EncodeToString(prvKey[:]))
	t.Logf("address is: [0x%s]", hex.EncodeToString(pubKey[:]))
	msg := []byte("hello world")
	sign := crypto.ED25519Sign(crypto.PrivateKey(prvKey), msg)
	valid := crypto.ED25519Verify(crypto.PublicKey(pubKey), msg, sign)
	if !valid{
		t.Error("check sign failed")
		return
	}
	t.Logf("sign msg [%s], checked passed with referred public key", msg)
	pubKey0 := crypto.RetrievePubkey(crypto.PrivateKey(prvKey))
	assert.Equal(t, crypto.PublicKey(pubKey0), crypto.PublicKey(pubKey), "retrieve public key from private key not matched")
}

func TestPartKeys(t *testing.T){
	var masterPubKey [32]byte
	var masterPrvKey [64]byte
	var partKeys []*PartKey
	masterPubKey, masterPrvKey, err := crypto.ED25519GenerateKey()
	if err != nil {
		t.Error(err)
		return
	}
	startRound := 1
	endRound := 10
	for r := startRound; r<=endRound; r++{
		k := new(PartKey)
		k.RoundID = uint64(r)
		k.MasterKey = masterPubKey
		k.PubKey, k.PrvKey, err = crypto.ED25519GenerateKey()
		data := []byte(hex.EncodeToString(k.PubKey[:])+strconv.Itoa(r))
		k.Sig = crypto.ED25519Sign(masterPrvKey, data)
		partKeys = append(partKeys, k)
	}
	msg := []byte("hello world")
	for r := startRound; r<=endRound; r++{
		sigForMSG := crypto.ED25519Sign(partKeys[r-1].PrvKey, msg)
		data := []byte(hex.EncodeToString(partKeys[r-1].PubKey[:])+strconv.Itoa(r))
		assert.Equal(t, crypto.ED25519Verify(partKeys[r-1].PubKey, msg, sigForMSG), true, "msg signed not passed")
		assert.Equal(t, crypto.ED25519Verify(masterPubKey, data, partKeys[r-1].Sig), true, "part key not controlled by the master key")
	}
}