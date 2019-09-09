package main

import (
	"awesome-algo/crypto"
	"awesome-algo/crypto/sortition"
	crypto2 "github.com/algorand/go-algorand/crypto"
	sortition2 "github.com/algorand/go-algorand/data/committee/sortition"
	"github.com/magiconair/properties/assert"
	"testing"
)

func TestSelect(t *testing.T){
	pubKey, prvKey := crypto.VRFKeygen()
	msg := []byte("hello world")
	proof, ok := crypto.VRFProve(prvKey, msg)
	assert.Equal(t, ok, true, "vrf proof failed")
	ok, output := crypto.VRFVerify(pubKey, proof, msg)
	assert.Equal(t, ok, true, "vrf verify failed")
	//fmt.Println(hex.EncodeToString(output[:]))
	var h crypto.Digest
	h = crypto.Hash(output[:])
	selected1 := sortition.Select(1500000, 2000000, 150, h)
	selected2 := sortition2.Select(1500000, 2000000, 150, crypto2.Digest(h))
	assert.Equal(t, selected1, selected2, "selected not matched")
}
