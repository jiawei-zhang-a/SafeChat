// Implementation of a forward-secure, end-to-end encrypted messaging client
// supporting key compromise recovery and out-of-order message delivery.
// Directly inspired by Signal/Double-ratchet protocol but missing a few
// features. No asynchronous handshake support (pre-keys) for example.
//
// SECURITY WARNING: This code is meant for educational purposes and may
// contain vulnerabilities or other bugs. Please do not use it for
// security-critical applications.
//
// GRADING NOTES: This is the only file you need to modify for this assignment.
// You may add additional support files if desired. You should modify this file
// to implement the intended protocol, but preserve the function signatures
// for the following methods to ensure your implementation will work with
// standard test code:
//
// *NewChatter
// *EndSession
// *InitiateHandshake
// *ReturnHandshake
// *FinalizeHandshake
// *SendMessage
// *ReceiveMessage
//
// In addition, you'll need to keep all of the following structs' fields:
//
// *Chatter
// *Session
// *Message
//
// You may add fields if needed (not necessary) but don't rename or delete
// any existing fields.
//
// Original version
// Joseph Bonneau February 2019

package chatterbox

import (
	//	"bytes" //un-comment for helpers like bytes.equal
	"encoding/binary"
	"errors"
	//"golang.org/x/tools/go/analysis/passes/nilfunc"
	//"golang.org/x/text/message"
	//	"fmt" //un-comment if you want to do any debug printing.
)

func StoreInCache(Session *Session, first int, last int) []int {
	KeyMaps := make([]int, 0)
	for i := first; i < last; i++ {
		Session.ReceiveChain = Session.ReceiveChain.DeriveKey(CHAIN_LABEL)
		Session.CachedReceiveKeys[i] = Session.ReceiveChain.DeriveKey(KEY_LABEL)
		KeyMaps = append(KeyMaps, i)
	}
	return KeyMaps
}

// Labels for key derivation

// Label for generating a check key from the initial root.
// Used for verifying the results of a handshake out-of-band.
const HANDSHAKE_CHECK_LABEL byte = 0x11

// Label for ratcheting the root key after deriving a key chain from it
const ROOT_LABEL = 0x22

// Label for ratcheting the main chain of keys
const CHAIN_LABEL = 0x33

// Label for deriving message keys from chain keys
const KEY_LABEL = 0x44

// Chatter represents a chat participant. Each Chatter has a single long-term
// key Identity, and a map of open sessions with other users (indexed by their
// identity keys). You should not need to modify this.
type Chatter struct {
	Identity *KeyPair
	Sessions map[PublicKey]*Session
}

// Session represents an open session between one chatter and another.
// You should not need to modify this, though you can add additional fields
// if you want to.
type Session struct {
	MyDHRatchet       *KeyPair
	PartnerDHRatchet  *PublicKey
	RootChain         *SymmetricKey
	SendChain         *SymmetricKey
	ReceiveChain      *SymmetricKey
	CachedReceiveKeys map[int]*SymmetricKey
	SendCounter       int
	LastUpdate        int
	ReceiveCounter    int
}

// Message represents a message as sent over an untrusted network.
// The first 5 fields are send unencrypted (but should be authenticated).
// The ciphertext contains the (encrypted) communication payload.
// You should not need to modify this.
type Message struct {
	Sender        *PublicKey
	Receiver      *PublicKey
	NextDHRatchet *PublicKey
	Counter       int
	LastUpdate    int
	Ciphertext    []byte
	IV            []byte
}

// EncodeAdditionalData encodes all of the non-ciphertext fields of a message
// into a single byte array, suitable for use as additional authenticated data
// in an AEAD scheme.
func (m *Message) EncodeAdditionalData() []byte {
	buf := make([]byte, 8+3*FINGERPRINT_LENGTH)

	binary.LittleEndian.PutUint32(buf, uint32(m.Counter))
	binary.LittleEndian.PutUint32(buf[4:], uint32(m.LastUpdate))

	if m.Sender != nil {
		copy(buf[8:], m.Sender.Fingerprint())
	}
	if m.Receiver != nil {
		copy(buf[8+FINGERPRINT_LENGTH:], m.Receiver.Fingerprint())
	}
	if m.NextDHRatchet != nil {
		copy(buf[8+2*FINGERPRINT_LENGTH:], m.NextDHRatchet.Fingerprint())
	}

	return buf
}

// NewChatter creates and initializes a new Chatter object. A long-term
// identity key is created and the map of sessions is initialized.
// You should not need to modify this code.
func NewChatter() *Chatter {
	c := new(Chatter)
	c.Identity = GenerateKeyPair()
	c.Sessions = make(map[PublicKey]*Session)
	return c
}

// EndSession erases all data for a session with the designated partner.
// All outstanding key material should be zeroized and the session erased.
func (c *Chatter) EndSession(partnerIdentity *PublicKey) error {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return errors.New("Don't have that session open to tear down")
	}

	delete(c.Sessions, *partnerIdentity)

	// TODO: your code here to zeroize remaining state

	return nil
}

// InitiateHandshake prepares the first message sent in a handshake, containing
// an ephemeral DH share. The partner which calls this method is the initiator.
func (c *Chatter) InitiateHandshake(partnerIdentity *PublicKey) (*PublicKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return nil, errors.New("Already have session open")
	}

	c.Sessions[*partnerIdentity] = &Session{
		MyDHRatchet:       GenerateKeyPair(), // ephemeral DH key
		PartnerDHRatchet:  nil,
		CachedReceiveKeys: make(map[int]*SymmetricKey),
		SendCounter:       0,
		LastUpdate:        0,
		ReceiveCounter:    0,
	}

	// Return Alice's ephemeral public key
	return &c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey, nil
}

// ReturnHandshake prepares the second message sent in a handshake, containing
// an ephemeral DH share. The partner which calls this method is the responder.
func (c *Chatter) ReturnHandshake(partnerIdentity,
	partnerEphemeral *PublicKey) (*PublicKey, *SymmetricKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return nil, nil, errors.New("Already have session open")
	}

	c.Sessions[*partnerIdentity] = &Session{
		MyDHRatchet:       GenerateKeyPair(), // ephemeral DH key
		PartnerDHRatchet:  partnerEphemeral,
		CachedReceiveKeys: make(map[int]*SymmetricKey),
		SendCounter:       0,
		LastUpdate:        0,
		ReceiveCounter:    0,
	}

	// Derive the root key
	g_Ab := DHCombine(partnerIdentity, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey)
	g_aB := DHCombine(partnerEphemeral, &c.Identity.PrivateKey)
	g_ab := DHCombine(partnerEphemeral, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey)

	RootKey := CombineKeys(g_Ab, g_aB, g_ab)

	// Derive the handshake check key
	AuthKey := RootKey.DeriveKey(HANDSHAKE_CHECK_LABEL)

	//set the root chain
	c.Sessions[*partnerIdentity].RootChain = RootKey

	//set the receive chain
	c.Sessions[*partnerIdentity].ReceiveChain = RootKey.Duplicate()

	return &c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey, AuthKey, nil
}

// FinalizeHandshake lets the initiator receive the responder's ephemeral key
// and finalize the handshake.The partner which calls this method is the initiator.
func (c *Chatter) FinalizeHandshake(partnerIdentity,
	partnerEphemeral *PublicKey) (*SymmetricKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return nil, errors.New("Can't finalize session, not yet open")
	}

	//set the partner's ephemeral key aka DH ratchet
	c.Sessions[*partnerIdentity].PartnerDHRatchet = partnerEphemeral

	// Derive the root key
	g_Ab := DHCombine(partnerEphemeral, &c.Identity.PrivateKey)
	g_aB := DHCombine(partnerIdentity, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey)
	g_ab := DHCombine(partnerEphemeral, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey)

	RootKey := CombineKeys(g_Ab, g_aB, g_ab)

	// Derive the handshake check key
	AuthKey := RootKey.DeriveKey(HANDSHAKE_CHECK_LABEL)

	//set the root chain
	c.Sessions[*partnerIdentity].RootChain = RootKey

	//set the receive chain and send chain
	c.Sessions[*partnerIdentity].ReceiveChain = RootKey.Duplicate()
	c.Sessions[*partnerIdentity].SendChain = RootKey.Duplicate()

	return AuthKey, nil
}

// SendMessage is used to send the given plaintext string as a message.
// You'll need to implement the code to ratchet, derive keys and encrypt this message.
func (c *Chatter) SendMessage(partnerIdentity *PublicKey,
	plaintext string) (*Message, error) {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return nil, errors.New("Can't send message to partner with no open session")
	}

	//declare the message key
	var messageKey *SymmetricKey

	//Initialize the message
	message := &Message{
		Sender:        &c.Identity.PublicKey,
		Receiver:      partnerIdentity,
		NextDHRatchet: &c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey,
		Counter:       0,
		LastUpdate:    0,
		Ciphertext:    nil,
		IV:            NewIV(),
		
	}

	//if the send chain is not nil, ratchet the send chain
	if c.Sessions[*partnerIdentity].SendChain != nil {
		//Ratchet the send chain , delete the old sendchain key and get the message key
		chainKey := c.Sessions[*partnerIdentity].SendChain.DeriveKey(CHAIN_LABEL)
		c.Sessions[*partnerIdentity].SendChain.Zeroize()
		c.Sessions[*partnerIdentity].SendChain = chainKey
	} else { // if the send chain is nil, ratchet the root chain the the send chain

		//generate new key
		c.Sessions[*partnerIdentity].MyDHRatchet = GenerateKeyPair()
		message.NextDHRatchet = &c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey

		//Ratchet the root chain , delete the old rootchain key
		RatchetRoot := c.Sessions[*partnerIdentity].RootChain.DeriveKey(ROOT_LABEL)
		c.Sessions[*partnerIdentity].RootChain.Zeroize()
		NewDH := DHCombine(c.Sessions[*partnerIdentity].PartnerDHRatchet, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey)

		// Derive the rootchain by combining the new DH key with the ratcheted root key 
		c.Sessions[*partnerIdentity].RootChain = CombineKeys(RatchetRoot, NewDH)

		//derive the send chain
		c.Sessions[*partnerIdentity].SendChain = c.Sessions[*partnerIdentity].RootChain.DeriveKey(CHAIN_LABEL)

		// Update the last update counter
		c.Sessions[*partnerIdentity].LastUpdate = c.Sessions[*partnerIdentity].SendCounter + 1
	}

	// Increment the send counter
	c.Sessions[*partnerIdentity].SendCounter++

	//derive the message key
	messageKey = c.Sessions[*partnerIdentity].SendChain.DeriveKey(KEY_LABEL)

	// Update the last update counter and the message counter
	message.LastUpdate = c.Sessions[*partnerIdentity].LastUpdate 
	message.Counter = c.Sessions[*partnerIdentity].SendCounter

	// Encrypt the message with AES-GCM
	//iv := NewIV()
	message.Ciphertext = messageKey.AuthenticatedEncrypt(plaintext, message.EncodeAdditionalData(), message.IV)

	return message, nil
}
	
func (c *Chatter) ReceiveMessage(message *Message) (string, error) {
	if _, exists := c.Sessions[*message.Sender]; !exists {
		return "", errors.New("Can't receive message from partner with no open session")
	}

	// Store backup of chain state
	StoredRootChain := c.Sessions[*message.Sender].RootChain
	StoredReceiveChain := c.Sessions[*message.Sender].ReceiveChain
	StoredReceiveCounter := c.Sessions[*message.Sender].ReceiveCounter
	StoredPartnerDHRatchet := c.Sessions[*message.Sender].PartnerDHRatchet
	KeyMaps := make([]int, 0)

	// variable to track if we ratchet the chain
	RatchetOrNot := false

	switch {
	// 1) Sequential message
	case message.Counter == c.Sessions[*message.Sender].ReceiveCounter + 1:
		// Otherwise the message is in sequence
		if message.LastUpdate <= c.Sessions[*message.Sender].ReceiveCounter {
			c.Sessions[*message.Sender].ReceiveChain = c.Sessions[*message.Sender].ReceiveChain.DeriveKey(CHAIN_LABEL)
		} else {
			//Ratchet the root chain
			RatchetOrNot = true
			RootKey := c.Sessions[*message.Sender].RootChain.DeriveKey(ROOT_LABEL)
			c.Sessions[*message.Sender].PartnerDHRatchet = message.NextDHRatchet
			DH := DHCombine(c.Sessions[*message.Sender].PartnerDHRatchet, &c.Sessions[*message.Sender].MyDHRatchet.PrivateKey)
			c.Sessions[*message.Sender].RootChain = CombineKeys(RootKey, DH)
			c.Sessions[*message.Sender].ReceiveChain = c.Sessions[*message.Sender].RootChain.DeriveKey(CHAIN_LABEL)
		}

	// 2) Early Message
	case message.Counter > c.Sessions[*message.Sender].ReceiveCounter+1:
		// Message came in early
		if message.LastUpdate > c.Sessions[*message.Sender].ReceiveCounter {
			KeyMaps = append(KeyMaps, StoreInCache(c.Sessions[*message.Sender], c.Sessions[*message.Sender].ReceiveCounter+1, message.LastUpdate)...)
			//Ratchet the root chain
			RatchetOrNot = true
			RootKey := c.Sessions[*message.Sender].RootChain.DeriveKey(ROOT_LABEL)
			c.Sessions[*message.Sender].PartnerDHRatchet = message.NextDHRatchet
			DH := DHCombine(c.Sessions[*message.Sender].PartnerDHRatchet, &c.Sessions[*message.Sender].MyDHRatchet.PrivateKey)
			c.Sessions[*message.Sender].RootChain = CombineKeys(RootKey, DH)
			c.Sessions[*message.Sender].ReceiveChain = c.Sessions[*message.Sender].RootChain.DeriveKey(CHAIN_LABEL)
			
			if message.LastUpdate != message.Counter {
				c.Sessions[*message.Sender].CachedReceiveKeys[message.LastUpdate] = c.Sessions[*message.Sender].ReceiveChain.DeriveKey(KEY_LABEL)
				KeyMaps = append(KeyMaps, message.LastUpdate)
				KeyMaps = append(KeyMaps, StoreInCache(c.Sessions[*message.Sender], message.LastUpdate+1, message.Counter)...)
				c.Sessions[*message.Sender].ReceiveChain = c.Sessions[*message.Sender].ReceiveChain.DeriveKey(CHAIN_LABEL)
			}
		} else {
			KeyMaps = append(KeyMaps, StoreInCache(c.Sessions[*message.Sender], c.Sessions[*message.Sender].ReceiveCounter+1, message.Counter)...)
			c.Sessions[*message.Sender].ReceiveChain = c.Sessions[*message.Sender].ReceiveChain.DeriveKey(CHAIN_LABEL)
		}		
	
	// 3) Late Message
	case message.Counter < c.Sessions[*message.Sender].ReceiveCounter:
		// Handling late messages
		messageKey := c.Sessions[*message.Sender].CachedReceiveKeys[message.Counter]
		extra := message.EncodeAdditionalData()
		plaintext, err := messageKey.AuthenticatedDecrypt(message.Ciphertext, extra, message.IV)
		if err == nil {
			c.Sessions[*message.Sender].CachedReceiveKeys[message.Counter].Zeroize()
		}
		return plaintext, err
	}

	/////////////////////////////////////////////////////////
	// Decrypt the message if the receive chain is up to date
	/////////////////////////////////////////////////////////

	// Derive the message key
	messageKey := c.Sessions[*message.Sender].ReceiveChain.DeriveKey(KEY_LABEL)
	c.Sessions[*message.Sender].ReceiveCounter = message.Counter
	plaintext, err := messageKey.AuthenticatedDecrypt(message.Ciphertext, message.EncodeAdditionalData(), message.IV)
	
	// Deal with tampering and recover from backup
	if err == nil {
		// Zeroize the old receive key and if we've ratcheted, we need to do some more zeroizing
		if StoredReceiveChain != nil {
			// Zeroize the receive key
			StoredReceiveChain.Zeroize()
		}
		if RatchetOrNot {
			// Zeroize the root key
			StoredRootChain.Zeroize()
			c.Sessions[*message.Sender].SendChain.Zeroize()
			c.Sessions[*message.Sender].SendChain = nil
			c.Sessions[*message.Sender].MyDHRatchet.Zeroize()
		}
	} else { // If no errors, zeroize the stored backup keys
		// Zeroize the old receive key and if we've ratcheted, we need to do some more zeroizing
		c.Sessions[*message.Sender].RootChain = StoredRootChain
		c.Sessions[*message.Sender].ReceiveChain = StoredReceiveChain
		c.Sessions[*message.Sender].ReceiveCounter = StoredReceiveCounter
		c.Sessions[*message.Sender].PartnerDHRatchet = StoredPartnerDHRatchet
		// Delete all the cached keys
		for _, index := range KeyMaps {
			delete(c.Sessions[*message.Sender].CachedReceiveKeys, index)
		}
	}

	return plaintext, err
}

