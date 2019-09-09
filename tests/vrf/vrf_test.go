package main

import (
	"awesome-algo/crypto"
	"encoding/hex"
	"github.com/magiconair/properties/assert"
	"testing"
)

func TestKeyPair(t *testing.T){
	var pubKey crypto.VrfPubkey
	var prvKey crypto.VrfPrivkey
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
	t.Log("check sign msg passed")
	pubKey0 := crypto.RetrievePubkey(crypto.PrivateKey(prvKey))
	assert.Equal(t, pubKey0[:], pubKey[:], "retrieve public key from private key not matched")
}

func TestVRF(t *testing.T) {
	var pubKey crypto.VrfPubkey
	var prvKey crypto.VrfPrivkey
	var proof crypto.VrfProof
	pubKey, prvKey = crypto.VRFKeygen()
	t.Logf("public key is: [0x%s]", hex.EncodeToString(pubKey[:]))
	t.Logf("private key is: [0x%s]", hex.EncodeToString(prvKey[:]))
	t.Logf("address is: [0x%s]", hex.EncodeToString(pubKey[:]))

	msg := []byte("hello world")
	proof,ok := crypto.VRFProve(prvKey, msg)
	t.Logf("vrf proof is: [0x%s]", hex.EncodeToString(proof[:]))
	assert.Equal(t, ok, true, "proof failed")
	ok, output := crypto.VRFVerify(pubKey, proof, msg)
	t.Logf("vrf output is: [0x%s]", hex.EncodeToString(output[:]))
	assert.Equal(t, ok, true, "verify proof failed")
}
