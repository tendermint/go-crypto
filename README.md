

# crypto
`import "github.com/tendermint/go-crypto"`

* [Overview](#pkg-overview)
* [Index](#pkg-index)
* [Subdirectories](#pkg-subdirectories)

## <a name="pkg-overview">Overview</a>



## <a name="pkg-index">Index</a>
* [Constants](#pkg-constants)
* [func CRandBytes(numBytes int) []byte](#CRandBytes)
* [func CRandHex(numDigits int) string](#CRandHex)
* [func CReader() io.Reader](#CReader)
* [func DecodeArmor(armorStr string) (blockType string, headers map[string]string, data []byte, err error)](#DecodeArmor)
* [func DecryptSymmetric(ciphertext []byte, secret []byte) (plaintext []byte, err error)](#DecryptSymmetric)
* [func EncodeArmor(blockType string, headers map[string]string, data []byte) string](#EncodeArmor)
* [func EncryptSymmetric(plaintext []byte, secret []byte) (ciphertext []byte)](#EncryptSymmetric)
* [func MixEntropy(seedBytes []byte)](#MixEntropy)
* [func Ripemd160(bytes []byte) []byte](#Ripemd160)
* [func Sha256(bytes []byte) []byte](#Sha256)
* [type PrivKey](#PrivKey)
  * [func PrivKeyFromBytes(privKeyBytes []byte) (privKey PrivKey, err error)](#PrivKeyFromBytes)
  * [func (p PrivKey) Bytes() []byte](#PrivKey.Bytes)
  * [func (p PrivKey) Empty() bool](#PrivKey.Empty)
  * [func (p PrivKey) MarshalJSON() ([]byte, error)](#PrivKey.MarshalJSON)
  * [func (p *PrivKey) UnmarshalJSON(data []byte) (err error)](#PrivKey.UnmarshalJSON)
  * [func (p PrivKey) Unwrap() PrivKeyInner](#PrivKey.Unwrap)
* [type PrivKeyEd25519](#PrivKeyEd25519)
  * [func GenPrivKeyEd25519() PrivKeyEd25519](#GenPrivKeyEd25519)
  * [func GenPrivKeyEd25519FromSecret(secret []byte) PrivKeyEd25519](#GenPrivKeyEd25519FromSecret)
  * [func (privKey PrivKeyEd25519) AssertIsPrivKeyInner()](#PrivKeyEd25519.AssertIsPrivKeyInner)
  * [func (privKey PrivKeyEd25519) Equals(other PrivKey) bool](#PrivKeyEd25519.Equals)
  * [func (privKey PrivKeyEd25519) Generate(index int) PrivKeyEd25519](#PrivKeyEd25519.Generate)
  * [func (p PrivKeyEd25519) MarshalJSON() ([]byte, error)](#PrivKeyEd25519.MarshalJSON)
  * [func (privKey PrivKeyEd25519) PubKey() PubKey](#PrivKeyEd25519.PubKey)
  * [func (privKey PrivKeyEd25519) Sign(msg []byte) Signature](#PrivKeyEd25519.Sign)
  * [func (privKey PrivKeyEd25519) String() string](#PrivKeyEd25519.String)
  * [func (privKey PrivKeyEd25519) ToCurve25519() *[32]byte](#PrivKeyEd25519.ToCurve25519)
  * [func (p *PrivKeyEd25519) UnmarshalJSON(enc []byte) error](#PrivKeyEd25519.UnmarshalJSON)
  * [func (privKey PrivKeyEd25519) Wrap() PrivKey](#PrivKeyEd25519.Wrap)
* [type PrivKeyInner](#PrivKeyInner)
* [type PrivKeySecp256k1](#PrivKeySecp256k1)
  * [func GenPrivKeySecp256k1() PrivKeySecp256k1](#GenPrivKeySecp256k1)
  * [func GenPrivKeySecp256k1FromSecret(secret []byte) PrivKeySecp256k1](#GenPrivKeySecp256k1FromSecret)
  * [func (privKey PrivKeySecp256k1) AssertIsPrivKeyInner()](#PrivKeySecp256k1.AssertIsPrivKeyInner)
  * [func (privKey PrivKeySecp256k1) Equals(other PrivKey) bool](#PrivKeySecp256k1.Equals)
  * [func (p PrivKeySecp256k1) MarshalJSON() ([]byte, error)](#PrivKeySecp256k1.MarshalJSON)
  * [func (privKey PrivKeySecp256k1) PubKey() PubKey](#PrivKeySecp256k1.PubKey)
  * [func (privKey PrivKeySecp256k1) Sign(msg []byte) Signature](#PrivKeySecp256k1.Sign)
  * [func (privKey PrivKeySecp256k1) String() string](#PrivKeySecp256k1.String)
  * [func (p *PrivKeySecp256k1) UnmarshalJSON(enc []byte) error](#PrivKeySecp256k1.UnmarshalJSON)
  * [func (privKey PrivKeySecp256k1) Wrap() PrivKey](#PrivKeySecp256k1.Wrap)
* [type PubKey](#PubKey)
  * [func PubKeyFromBytes(pubKeyBytes []byte) (pubKey PubKey, err error)](#PubKeyFromBytes)
  * [func (p PubKey) Bytes() []byte](#PubKey.Bytes)
  * [func (p PubKey) Empty() bool](#PubKey.Empty)
  * [func (pk PubKey) MarshalJSON() ([]byte, error)](#PubKey.MarshalJSON)
  * [func (pk *PubKey) UnmarshalJSON(data []byte) (err error)](#PubKey.UnmarshalJSON)
  * [func (pk PubKey) Unwrap() PubKeyInner](#PubKey.Unwrap)
* [type PubKeyEd25519](#PubKeyEd25519)
  * [func (pubKey PubKeyEd25519) Address() []byte](#PubKeyEd25519.Address)
  * [func (pubKey PubKeyEd25519) AssertIsPubKeyInner()](#PubKeyEd25519.AssertIsPubKeyInner)
  * [func (pubKey PubKeyEd25519) Equals(other PubKey) bool](#PubKeyEd25519.Equals)
  * [func (pubKey PubKeyEd25519) KeyString() string](#PubKeyEd25519.KeyString)
  * [func (p PubKeyEd25519) MarshalJSON() ([]byte, error)](#PubKeyEd25519.MarshalJSON)
  * [func (pubKey PubKeyEd25519) String() string](#PubKeyEd25519.String)
  * [func (pubKey PubKeyEd25519) ToCurve25519() *[32]byte](#PubKeyEd25519.ToCurve25519)
  * [func (p *PubKeyEd25519) UnmarshalJSON(enc []byte) error](#PubKeyEd25519.UnmarshalJSON)
  * [func (pubKey PubKeyEd25519) VerifyBytes(msg []byte, sig_ Signature) bool](#PubKeyEd25519.VerifyBytes)
  * [func (pubKey PubKeyEd25519) Wrap() PubKey](#PubKeyEd25519.Wrap)
* [type PubKeyInner](#PubKeyInner)
* [type PubKeySecp256k1](#PubKeySecp256k1)
  * [func (pubKey PubKeySecp256k1) Address() []byte](#PubKeySecp256k1.Address)
  * [func (pubKey PubKeySecp256k1) AssertIsPubKeyInner()](#PubKeySecp256k1.AssertIsPubKeyInner)
  * [func (pubKey PubKeySecp256k1) Equals(other PubKey) bool](#PubKeySecp256k1.Equals)
  * [func (pubKey PubKeySecp256k1) KeyString() string](#PubKeySecp256k1.KeyString)
  * [func (p PubKeySecp256k1) MarshalJSON() ([]byte, error)](#PubKeySecp256k1.MarshalJSON)
  * [func (pubKey PubKeySecp256k1) String() string](#PubKeySecp256k1.String)
  * [func (p *PubKeySecp256k1) UnmarshalJSON(enc []byte) error](#PubKeySecp256k1.UnmarshalJSON)
  * [func (pubKey PubKeySecp256k1) VerifyBytes(msg []byte, sig_ Signature) bool](#PubKeySecp256k1.VerifyBytes)
  * [func (pubKey PubKeySecp256k1) Wrap() PubKey](#PubKeySecp256k1.Wrap)
* [type Signature](#Signature)
  * [func SignatureFromBytes(sigBytes []byte) (sig Signature, err error)](#SignatureFromBytes)
  * [func (s Signature) Bytes() []byte](#Signature.Bytes)
  * [func (sig Signature) Empty() bool](#Signature.Empty)
  * [func (sig Signature) MarshalJSON() ([]byte, error)](#Signature.MarshalJSON)
  * [func (sig *Signature) UnmarshalJSON(data []byte) (err error)](#Signature.UnmarshalJSON)
  * [func (sig Signature) Unwrap() SignatureInner](#Signature.Unwrap)
* [type SignatureEd25519](#SignatureEd25519)
  * [func (sig SignatureEd25519) AssertIsSignatureInner()](#SignatureEd25519.AssertIsSignatureInner)
  * [func (sig SignatureEd25519) Equals(other Signature) bool](#SignatureEd25519.Equals)
  * [func (sig SignatureEd25519) IsZero() bool](#SignatureEd25519.IsZero)
  * [func (sig SignatureEd25519) MarshalJSON() ([]byte, error)](#SignatureEd25519.MarshalJSON)
  * [func (sig SignatureEd25519) String() string](#SignatureEd25519.String)
  * [func (sig *SignatureEd25519) UnmarshalJSON(enc []byte) error](#SignatureEd25519.UnmarshalJSON)
  * [func (sig SignatureEd25519) Wrap() Signature](#SignatureEd25519.Wrap)
* [type SignatureInner](#SignatureInner)
* [type SignatureSecp256k1](#SignatureSecp256k1)
  * [func (sig SignatureSecp256k1) AssertIsSignatureInner()](#SignatureSecp256k1.AssertIsSignatureInner)
  * [func (sig SignatureSecp256k1) Equals(other Signature) bool](#SignatureSecp256k1.Equals)
  * [func (sig SignatureSecp256k1) IsZero() bool](#SignatureSecp256k1.IsZero)
  * [func (sig SignatureSecp256k1) MarshalJSON() ([]byte, error)](#SignatureSecp256k1.MarshalJSON)
  * [func (sig SignatureSecp256k1) String() string](#SignatureSecp256k1.String)
  * [func (sig *SignatureSecp256k1) UnmarshalJSON(enc []byte) error](#SignatureSecp256k1.UnmarshalJSON)
  * [func (sig SignatureSecp256k1) Wrap() Signature](#SignatureSecp256k1.Wrap)


#### <a name="pkg-files">Package files</a>
[armor.go](/src/github.com/tendermint/go-crypto/armor.go) [crypto.go](/src/github.com/tendermint/go-crypto/crypto.go) [ed25519.go](/src/github.com/tendermint/go-crypto/ed25519.go) [hash.go](/src/github.com/tendermint/go-crypto/hash.go) [priv_key.go](/src/github.com/tendermint/go-crypto/priv_key.go) [pub_key.go](/src/github.com/tendermint/go-crypto/pub_key.go) [random.go](/src/github.com/tendermint/go-crypto/random.go) [secp256k1.go](/src/github.com/tendermint/go-crypto/secp256k1.go) [signature.go](/src/github.com/tendermint/go-crypto/signature.go) [symmetric.go](/src/github.com/tendermint/go-crypto/symmetric.go) 


## <a name="pkg-constants">Constants</a>
``` go
const (
    TypeEd25519   = byte(0x01)
    TypeSecp256k1 = byte(0x02)
    NameEd25519   = "ed25519"
    NameSecp256k1 = "secp256k1"
)
```
Types of implementations




## <a name="CRandBytes">func</a> [CRandBytes](/src/target/random.go?s=698:734#L28)
``` go
func CRandBytes(numBytes int) []byte
```
This uses the OS and the Seed(s).



## <a name="CRandHex">func</a> [CRandHex](/src/target/random.go?s=924:959#L38)
``` go
func CRandHex(numDigits int) string
```
RandHex(24) gives 96 bits of randomness, strong enough for most purposes.



## <a name="CReader">func</a> [CReader](/src/target/random.go?s=1078:1102#L43)
``` go
func CReader() io.Reader
```
Returns a crand.Reader mixed with user-supplied entropy



## <a name="DecodeArmor">func</a> [DecodeArmor](/src/target/armor.go?s=596:699#L18)
``` go
func DecodeArmor(armorStr string) (blockType string, headers map[string]string, data []byte, err error)
```


## <a name="DecryptSymmetric">func</a> [DecryptSymmetric](/src/target/symmetric.go?s=1048:1133#L23)
``` go
func DecryptSymmetric(ciphertext []byte, secret []byte) (plaintext []byte, err error)
```
secret must be 32 bytes long. Use something like Sha256(Bcrypt(passphrase))
The ciphertext is (secretbox.Overhead + 24) bytes longer than the plaintext.



## <a name="EncodeArmor">func</a> [EncodeArmor](/src/target/armor.go?s=125:206#L1)
``` go
func EncodeArmor(blockType string, headers map[string]string, data []byte) string
```


## <a name="EncryptSymmetric">func</a> [EncryptSymmetric](/src/target/symmetric.go?s=356:430#L6)
``` go
func EncryptSymmetric(plaintext []byte, secret []byte) (ciphertext []byte)
```
secret must be 32 bytes long. Use something like Sha256(Bcrypt(passphrase))
The ciphertext is (secretbox.Overhead + 24) bytes longer than the plaintext.
NOTE: call crypto.MixEntropy() first.



## <a name="MixEntropy">func</a> [MixEntropy](/src/target/random.go?s=407:440#L13)
``` go
func MixEntropy(seedBytes []byte)
```
Mix additional bytes of randomness, e.g. from hardware, user-input, etc.
It is OK to call it multiple times.  It does not diminish security.



## <a name="Ripemd160">func</a> [Ripemd160](/src/target/hash.go?s=185:220#L4)
``` go
func Ripemd160(bytes []byte) []byte
```


## <a name="Sha256">func</a> [Sha256](/src/target/hash.go?s=78:110#L1)
``` go
func Sha256(bytes []byte) []byte
```



## <a name="PrivKey">type</a> [PrivKey](/src/target/priv_key.go?s=280:333#L5)
``` go
type PrivKey struct {
    PrivKeyInner `json:"unwrap"`
}
```






### <a name="PrivKeyFromBytes">func</a> [PrivKeyFromBytes](/src/target/priv_key.go?s=99:170#L1)
``` go
func PrivKeyFromBytes(privKeyBytes []byte) (privKey PrivKey, err error)
```




### <a name="PrivKey.Bytes">func</a> (PrivKey) [Bytes](/src/target/priv_key.go?s=587:618#L21)
``` go
func (p PrivKey) Bytes() []byte
```



### <a name="PrivKey.Empty">func</a> (PrivKey) [Empty](/src/target/priv_key.go?s=1190:1219#L46)
``` go
func (p PrivKey) Empty() bool
```



### <a name="PrivKey.MarshalJSON">func</a> (PrivKey) [MarshalJSON](/src/target/priv_key.go?s=652:698#L25)
``` go
func (p PrivKey) MarshalJSON() ([]byte, error)
```



### <a name="PrivKey.UnmarshalJSON">func</a> (\*PrivKey) [UnmarshalJSON](/src/target/priv_key.go?s=749:805#L29)
``` go
func (p *PrivKey) UnmarshalJSON(data []byte) (err error)
```



### <a name="PrivKey.Unwrap">func</a> (PrivKey) [Unwrap](/src/target/priv_key.go?s=1024:1062#L38)
``` go
func (p PrivKey) Unwrap() PrivKeyInner
```
Unwrap recovers the concrete interface safely (regardless of levels of embeds)




## <a name="PrivKeyEd25519">type</a> [PrivKeyEd25519](/src/target/ed25519.go?s=632:660#L17)
``` go
type PrivKeyEd25519 [64]byte
```
Implements PrivKey







### <a name="GenPrivKeyEd25519">func</a> [GenPrivKeyEd25519](/src/target/ed25519.go?s=2211:2250#L78)
``` go
func GenPrivKeyEd25519() PrivKeyEd25519
```

### <a name="GenPrivKeyEd25519FromSecret">func</a> [GenPrivKeyEd25519FromSecret](/src/target/ed25519.go?s=2498:2560#L87)
``` go
func GenPrivKeyEd25519FromSecret(secret []byte) PrivKeyEd25519
```
NOTE: secret should be the output of a KDF like bcrypt,
if it's derived from user input.





### <a name="PrivKeyEd25519.AssertIsPrivKeyInner">func</a> (PrivKeyEd25519) [AssertIsPrivKeyInner](/src/target/ed25519.go?s=662:714#L19)
``` go
func (privKey PrivKeyEd25519) AssertIsPrivKeyInner()
```



### <a name="PrivKeyEd25519.Equals">func</a> (PrivKeyEd25519) [Equals](/src/target/ed25519.go?s=1093:1149#L33)
``` go
func (privKey PrivKeyEd25519) Equals(other PrivKey) bool
```



### <a name="PrivKeyEd25519.Generate">func</a> (PrivKeyEd25519) [Generate](/src/target/ed25519.go?s=1894:1958#L64)
``` go
func (privKey PrivKeyEd25519) Generate(index int) PrivKeyEd25519
```
Deterministically generates new priv-key bytes from key.




### <a name="PrivKeyEd25519.MarshalJSON">func</a> (PrivKeyEd25519) [MarshalJSON](/src/target/ed25519.go?s=1285:1338#L41)
``` go
func (p PrivKeyEd25519) MarshalJSON() ([]byte, error)
```



### <a name="PrivKeyEd25519.PubKey">func</a> (PrivKeyEd25519) [PubKey](/src/target/ed25519.go?s=917:962#L27)
``` go
func (privKey PrivKeyEd25519) PubKey() PubKey
```



### <a name="PrivKeyEd25519.Sign">func</a> (PrivKeyEd25519) [Sign](/src/target/ed25519.go?s=719:775#L21)
``` go
func (privKey PrivKeyEd25519) Sign(msg []byte) Signature
```



### <a name="PrivKeyEd25519.String">func</a> (PrivKeyEd25519) [String](/src/target/ed25519.go?s=1742:1787#L59)
``` go
func (privKey PrivKeyEd25519) String() string
```



### <a name="PrivKeyEd25519.ToCurve25519">func</a> (PrivKeyEd25519) [ToCurve25519](/src/target/ed25519.go?s=1528:1582#L52)
``` go
func (privKey PrivKeyEd25519) ToCurve25519() *[32]byte
```



### <a name="PrivKeyEd25519.UnmarshalJSON">func</a> (\*PrivKeyEd25519) [UnmarshalJSON](/src/target/ed25519.go?s=1379:1435#L45)
``` go
func (p *PrivKeyEd25519) UnmarshalJSON(enc []byte) error
```



### <a name="PrivKeyEd25519.Wrap">func</a> (PrivKeyEd25519) [Wrap](/src/target/ed25519.go?s=2136:2180#L74)
``` go
func (privKey PrivKeyEd25519) Wrap() PrivKey
```



## <a name="PrivKeyInner">type</a> [PrivKeyInner](/src/target/priv_key.go?s=447:585#L13)
``` go
type PrivKeyInner interface {
    AssertIsPrivKeyInner()
    Sign(msg []byte) Signature
    PubKey() PubKey
    Equals(PrivKey) bool
    Wrap() PrivKey
}
```
DO NOT USE THIS INTERFACE.
You probably want to use PubKey










## <a name="PrivKeySecp256k1">type</a> [PrivKeySecp256k1](/src/target/secp256k1.go?s=598:628#L16)
``` go
type PrivKeySecp256k1 [32]byte
```
Implements PrivKey







### <a name="GenPrivKeySecp256k1">func</a> [GenPrivKeySecp256k1](/src/target/secp256k1.go?s=2105:2148#L76)
``` go
func GenPrivKeySecp256k1() PrivKeySecp256k1
```

### <a name="GenPrivKeySecp256k1FromSecret">func</a> [GenPrivKeySecp256k1FromSecret](/src/target/secp256k1.go?s=2470:2536#L86)
``` go
func GenPrivKeySecp256k1FromSecret(secret []byte) PrivKeySecp256k1
```
NOTE: secret should be the output of a KDF like bcrypt,
if it's derived from user input.





### <a name="PrivKeySecp256k1.AssertIsPrivKeyInner">func</a> (PrivKeySecp256k1) [AssertIsPrivKeyInner](/src/target/secp256k1.go?s=630:684#L18)
``` go
func (privKey PrivKeySecp256k1) AssertIsPrivKeyInner()
```



### <a name="PrivKeySecp256k1.Equals">func</a> (PrivKeySecp256k1) [Equals](/src/target/secp256k1.go?s=1170:1228#L36)
``` go
func (privKey PrivKeySecp256k1) Equals(other PrivKey) bool
```



### <a name="PrivKeySecp256k1.MarshalJSON">func</a> (PrivKeySecp256k1) [MarshalJSON](/src/target/secp256k1.go?s=1370:1425#L44)
``` go
func (p PrivKeySecp256k1) MarshalJSON() ([]byte, error)
```



### <a name="PrivKeySecp256k1.PubKey">func</a> (PrivKeySecp256k1) [PubKey](/src/target/secp256k1.go?s=960:1007#L29)
``` go
func (privKey PrivKeySecp256k1) PubKey() PubKey
```



### <a name="PrivKeySecp256k1.Sign">func</a> (PrivKeySecp256k1) [Sign](/src/target/secp256k1.go?s=689:747#L20)
``` go
func (privKey PrivKeySecp256k1) Sign(msg []byte) Signature
```



### <a name="PrivKeySecp256k1.String">func</a> (PrivKeySecp256k1) [String](/src/target/secp256k1.go?s=1617:1664#L55)
``` go
func (privKey PrivKeySecp256k1) String() string
```



### <a name="PrivKeySecp256k1.UnmarshalJSON">func</a> (\*PrivKeySecp256k1) [UnmarshalJSON](/src/target/secp256k1.go?s=1466:1524#L48)
``` go
func (p *PrivKeySecp256k1) UnmarshalJSON(enc []byte) error
```



### <a name="PrivKeySecp256k1.Wrap">func</a> (PrivKeySecp256k1) [Wrap](/src/target/secp256k1.go?s=1713:1759#L59)
``` go
func (privKey PrivKeySecp256k1) Wrap() PrivKey
```



## <a name="PubKey">type</a> [PubKey](/src/target/pub_key.go?s=274:325#L5)
``` go
type PubKey struct {
    PubKeyInner `json:"unwrap"`
}
```






### <a name="PubKeyFromBytes">func</a> [PubKeyFromBytes](/src/target/pub_key.go?s=99:166#L1)
``` go
func PubKeyFromBytes(pubKeyBytes []byte) (pubKey PubKey, err error)
```




### <a name="PubKey.Bytes">func</a> (PubKey) [Bytes](/src/target/pub_key.go?s=611:641#L22)
``` go
func (p PubKey) Bytes() []byte
```



### <a name="PubKey.Empty">func</a> (PubKey) [Empty](/src/target/pub_key.go?s=1211:1239#L47)
``` go
func (p PubKey) Empty() bool
```



### <a name="PubKey.MarshalJSON">func</a> (PubKey) [MarshalJSON](/src/target/pub_key.go?s=675:721#L26)
``` go
func (pk PubKey) MarshalJSON() ([]byte, error)
```



### <a name="PubKey.UnmarshalJSON">func</a> (\*PubKey) [UnmarshalJSON](/src/target/pub_key.go?s=771:827#L30)
``` go
func (pk *PubKey) UnmarshalJSON(data []byte) (err error)
```



### <a name="PubKey.Unwrap">func</a> (PubKey) [Unwrap](/src/target/pub_key.go?s=1044:1081#L39)
``` go
func (pk PubKey) Unwrap() PubKeyInner
```
Unwrap recovers the concrete interface safely (regardless of levels of embeds)




## <a name="PubKeyEd25519">type</a> [PubKeyEd25519](/src/target/ed25519.go?s=2884:2911#L100)
``` go
type PubKeyEd25519 [32]byte
```
Implements PubKeyInner










### <a name="PubKeyEd25519.Address">func</a> (PubKeyEd25519) [Address](/src/target/ed25519.go?s=2967:3011#L104)
``` go
func (pubKey PubKeyEd25519) Address() []byte
```



### <a name="PubKeyEd25519.AssertIsPubKeyInner">func</a> (PubKeyEd25519) [AssertIsPubKeyInner](/src/target/ed25519.go?s=2913:2962#L102)
``` go
func (pubKey PubKeyEd25519) AssertIsPubKeyInner()
```



### <a name="PubKeyEd25519.Equals">func</a> (PubKeyEd25519) [Equals](/src/target/ed25519.go?s=4440:4493#L160)
``` go
func (pubKey PubKeyEd25519) Equals(other PubKey) bool
```



### <a name="PubKeyEd25519.KeyString">func</a> (PubKeyEd25519) [KeyString](/src/target/ed25519.go?s=4355:4401#L156)
``` go
func (pubKey PubKeyEd25519) KeyString() string
```
Must return the full bytes in hex.
Used for map keying, etc.




### <a name="PubKeyEd25519.MarshalJSON">func</a> (PubKeyEd25519) [MarshalJSON](/src/target/ed25519.go?s=3647:3699#L128)
``` go
func (p PubKeyEd25519) MarshalJSON() ([]byte, error)
```



### <a name="PubKeyEd25519.String">func</a> (PubKeyEd25519) [String](/src/target/ed25519.go?s=4191:4234#L150)
``` go
func (pubKey PubKeyEd25519) String() string
```



### <a name="PubKeyEd25519.ToCurve25519">func</a> (PubKeyEd25519) [ToCurve25519](/src/target/ed25519.go?s=3953:4005#L141)
``` go
func (pubKey PubKeyEd25519) ToCurve25519() *[32]byte
```
For use with golang/crypto/nacl/box
If error, returns nil.




### <a name="PubKeyEd25519.UnmarshalJSON">func</a> (\*PubKeyEd25519) [UnmarshalJSON](/src/target/ed25519.go?s=3740:3795#L132)
``` go
func (p *PubKeyEd25519) UnmarshalJSON(enc []byte) error
```



### <a name="PubKeyEd25519.VerifyBytes">func</a> (PubKeyEd25519) [VerifyBytes](/src/target/ed25519.go?s=3335:3407#L117)
``` go
func (pubKey PubKeyEd25519) VerifyBytes(msg []byte, sig_ Signature) bool
```



### <a name="PubKeyEd25519.Wrap">func</a> (PubKeyEd25519) [Wrap](/src/target/ed25519.go?s=4627:4668#L168)
``` go
func (pubKey PubKeyEd25519) Wrap() PubKey
```



## <a name="PubKeyInner">type</a> [PubKeyInner](/src/target/pub_key.go?s=437:609#L13)
``` go
type PubKeyInner interface {
    AssertIsPubKeyInner()
    Address() []byte
    KeyString() string
    VerifyBytes(msg []byte, sig Signature) bool
    Equals(PubKey) bool
    Wrap() PubKey
}
```
DO NOT USE THIS INTERFACE.
You probably want to use PubKey










## <a name="PubKeySecp256k1">type</a> [PubKeySecp256k1](/src/target/secp256k1.go?s=2988:3017#L101)
``` go
type PubKeySecp256k1 [33]byte
```
Implements PubKey.
Compressed pubkey (just the x-cord),
prefixed with 0x02 or 0x03, depending on the y-cord.










### <a name="PubKeySecp256k1.Address">func</a> (PubKeySecp256k1) [Address](/src/target/secp256k1.go?s=3140:3186#L106)
``` go
func (pubKey PubKeySecp256k1) Address() []byte
```
Implements Bitcoin style addresses: RIPEMD160(SHA256(pubkey))




### <a name="PubKeySecp256k1.AssertIsPubKeyInner">func</a> (PubKeySecp256k1) [AssertIsPubKeyInner](/src/target/secp256k1.go?s=3019:3070#L103)
``` go
func (pubKey PubKeySecp256k1) AssertIsPubKeyInner()
```



### <a name="PubKeySecp256k1.Equals">func</a> (PubKeySecp256k1) [Equals](/src/target/secp256k1.go?s=4368:4423#L155)
``` go
func (pubKey PubKeySecp256k1) Equals(other PubKey) bool
```



### <a name="PubKeySecp256k1.KeyString">func</a> (PubKeySecp256k1) [KeyString](/src/target/secp256k1.go?s=4281:4329#L151)
``` go
func (pubKey PubKeySecp256k1) KeyString() string
```
Must return the full bytes in hex.
Used for map keying, etc.




### <a name="PubKeySecp256k1.MarshalJSON">func</a> (PubKeySecp256k1) [MarshalJSON](/src/target/secp256k1.go?s=3868:3922#L134)
``` go
func (p PubKeySecp256k1) MarshalJSON() ([]byte, error)
```



### <a name="PubKeySecp256k1.String">func</a> (PubKeySecp256k1) [String](/src/target/secp256k1.go?s=4113:4158#L145)
``` go
func (pubKey PubKeySecp256k1) String() string
```



### <a name="PubKeySecp256k1.UnmarshalJSON">func</a> (\*PubKeySecp256k1) [UnmarshalJSON](/src/target/secp256k1.go?s=3963:4020#L138)
``` go
func (p *PubKeySecp256k1) UnmarshalJSON(enc []byte) error
```



### <a name="PubKeySecp256k1.VerifyBytes">func</a> (PubKeySecp256k1) [VerifyBytes](/src/target/secp256k1.go?s=3417:3491#L116)
``` go
func (pubKey PubKeySecp256k1) VerifyBytes(msg []byte, sig_ Signature) bool
```



### <a name="PubKeySecp256k1.Wrap">func</a> (PubKeySecp256k1) [Wrap](/src/target/secp256k1.go?s=4563:4606#L163)
``` go
func (pubKey PubKeySecp256k1) Wrap() PubKey
```



## <a name="Signature">type</a> [Signature](/src/target/signature.go?s=268:325#L5)
``` go
type Signature struct {
    SignatureInner `json:"unwrap"`
}
```






### <a name="SignatureFromBytes">func</a> [SignatureFromBytes](/src/target/signature.go?s=99:166#L1)
``` go
func SignatureFromBytes(sigBytes []byte) (sig Signature, err error)
```




### <a name="Signature.Bytes">func</a> (Signature) [Bytes](/src/target/signature.go?s=576:609#L21)
``` go
func (s Signature) Bytes() []byte
```



### <a name="Signature.Empty">func</a> (Signature) [Empty](/src/target/signature.go?s=1207:1240#L46)
``` go
func (sig Signature) Empty() bool
```



### <a name="Signature.MarshalJSON">func</a> (Signature) [MarshalJSON](/src/target/signature.go?s=643:693#L25)
``` go
func (sig Signature) MarshalJSON() ([]byte, error)
```



### <a name="Signature.UnmarshalJSON">func</a> (\*Signature) [UnmarshalJSON](/src/target/signature.go?s=744:804#L29)
``` go
func (sig *Signature) UnmarshalJSON(data []byte) (err error)
```



### <a name="Signature.Unwrap">func</a> (Signature) [Unwrap](/src/target/signature.go?s=1025:1069#L38)
``` go
func (sig Signature) Unwrap() SignatureInner
```
Unwrap recovers the concrete interface safely (regardless of levels of embeds)




## <a name="SignatureEd25519">type</a> [SignatureEd25519](/src/target/ed25519.go?s=4805:4835#L177)
``` go
type SignatureEd25519 [64]byte
```
Implements Signature










### <a name="SignatureEd25519.AssertIsSignatureInner">func</a> (SignatureEd25519) [AssertIsSignatureInner](/src/target/ed25519.go?s=4837:4889#L179)
``` go
func (sig SignatureEd25519) AssertIsSignatureInner()
```



### <a name="SignatureEd25519.Equals">func</a> (SignatureEd25519) [Equals](/src/target/ed25519.go?s=5066:5122#L185)
``` go
func (sig SignatureEd25519) Equals(other Signature) bool
```



### <a name="SignatureEd25519.IsZero">func</a> (SignatureEd25519) [IsZero](/src/target/ed25519.go?s=4894:4935#L181)
``` go
func (sig SignatureEd25519) IsZero() bool
```



### <a name="SignatureEd25519.MarshalJSON">func</a> (SignatureEd25519) [MarshalJSON](/src/target/ed25519.go?s=5256:5313#L193)
``` go
func (sig SignatureEd25519) MarshalJSON() ([]byte, error)
```



### <a name="SignatureEd25519.String">func</a> (SignatureEd25519) [String](/src/target/ed25519.go?s=4962:5005#L183)
``` go
func (sig SignatureEd25519) String() string
```



### <a name="SignatureEd25519.UnmarshalJSON">func</a> (\*SignatureEd25519) [UnmarshalJSON](/src/target/ed25519.go?s=5356:5416#L197)
``` go
func (sig *SignatureEd25519) UnmarshalJSON(enc []byte) error
```



### <a name="SignatureEd25519.Wrap">func</a> (SignatureEd25519) [Wrap](/src/target/ed25519.go?s=5511:5555#L204)
``` go
func (sig SignatureEd25519) Wrap() Signature
```



## <a name="SignatureInner">type</a> [SignatureInner](/src/target/signature.go?s=441:574#L13)
``` go
type SignatureInner interface {
    AssertIsSignatureInner()
    IsZero() bool
    String() string
    Equals(Signature) bool
    Wrap() Signature
}
```
DO NOT USE THIS INTERFACE.
You probably want to use Signature.










## <a name="SignatureSecp256k1">type</a> [SignatureSecp256k1](/src/target/secp256k1.go?s=4745:4775#L172)
``` go
type SignatureSecp256k1 []byte
```
Implements Signature










### <a name="SignatureSecp256k1.AssertIsSignatureInner">func</a> (SignatureSecp256k1) [AssertIsSignatureInner](/src/target/secp256k1.go?s=4777:4831#L174)
``` go
func (sig SignatureSecp256k1) AssertIsSignatureInner()
```



### <a name="SignatureSecp256k1.Equals">func</a> (SignatureSecp256k1) [Equals](/src/target/secp256k1.go?s=5012:5070#L180)
``` go
func (sig SignatureSecp256k1) Equals(other Signature) bool
```



### <a name="SignatureSecp256k1.IsZero">func</a> (SignatureSecp256k1) [IsZero](/src/target/secp256k1.go?s=4836:4879#L176)
``` go
func (sig SignatureSecp256k1) IsZero() bool
```



### <a name="SignatureSecp256k1.MarshalJSON">func</a> (SignatureSecp256k1) [MarshalJSON](/src/target/secp256k1.go?s=5205:5264#L187)
``` go
func (sig SignatureSecp256k1) MarshalJSON() ([]byte, error)
```



### <a name="SignatureSecp256k1.String">func</a> (SignatureSecp256k1) [String](/src/target/secp256k1.go?s=4906:4951#L178)
``` go
func (sig SignatureSecp256k1) String() string
```



### <a name="SignatureSecp256k1.UnmarshalJSON">func</a> (\*SignatureSecp256k1) [UnmarshalJSON](/src/target/secp256k1.go?s=5304:5366#L191)
``` go
func (sig *SignatureSecp256k1) UnmarshalJSON(enc []byte) error
```



### <a name="SignatureSecp256k1.Wrap">func</a> (SignatureSecp256k1) [Wrap](/src/target/secp256k1.go?s=5424:5470#L195)
``` go
func (sig SignatureSecp256k1) Wrap() Signature
```







- - -
Generated by [godoc2md](http://godoc.org/github.com/davecheney/godoc2md)
