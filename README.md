# crypto-gost

A thin Clojure warpper for Bouncycastle library (https://bouncycastle.org) to work with GOST algorithms - Russian cryptographic standards.


This library provides functions to work with: 
* encryption, mac (imito) using GOST 28147-89,
* digest, hmac  using GOST3411-94/2012 256 and 512 bits, 
* signature with GOST3410-2001
* key generation: secret, public/private, password based


## Usage

Add dependencies to your project:

```clojure
:dependencies [[org.bouncycastle/bcprov-jdk15on "1.57"]
               [crypto-gost "0.1"]]
```

Note: if you use Oracle JDK then  Bouncycastle jar should be in class path as separate library, not in uberjar, cause its content is signed.
In uberjar Oracle JDK throws java.security.NoSuchProviderException: JCE cannot authenticate the provider BC.
Use Open JDK to avoid problems with uberjar or as separate library in class path with Oracle JDK. 

Add necessary namespaces to ns form:

```clojure
(:require [crypto-gost.common]
            [crypto-gost.encrypt]
            [crypto-gost.digest]
            [crypto-gost.sign])
(:import java.security.SecureRandom)
```

### Key generation

To generate secret key for GOST 28147-89 using Java SecureRandom use crypto-gost.encrypt/gen-secret-key.
gen-secret-key returns generated key as bytes array 32 bytes length:

```clojure
  ;; secret key generation
  (let [secret-key (crypto-gost.encrypt/gen-secret-key)
        key-hex (crypto-gost.common/bytes-to-hex secret-key)]
    key-hex)
  ;; => "f60e38bc57b61c8201c7dd70f3859fc6eb6db2c65be7518ea2caef6ae2de35f2"
```

To generate secret key from ^String password use crypto-gost.encrypt/gen-secret-key-from-pwd.
gen-secret-key-from-pwd returns 32 bytes length secret key.

```clojure
 ;; pbe secret key generation
  (let [secret-key (crypto-gost.encrypt/gen-secret-key-from-pwd "MyPassword12")
        key-hex (crypto-gost.common/bytes-to-hex secret-key)]
    key-hex)
;; => "340fb3b14f0d554e683a85c35ae9d67d7002f8c716eac6652f5bfc5f1e764536"
```
Note: calling gen-secret-key-from-pwd with same password always returns same secret key value.

To generate private and public keypair for GOST3410-2001 use crypto-gost.sign/gen-keypair.

```clojure
 ;;generate GOST 3410-2001 KeyPair, save it to a files "gost-keypair.priv" / "gost-keypair.pub"
 ;;and then load it from files.
  (let [key-pair (crypto-gost.sign/gen-keypair)
        _ (crypto-gost.sign/save-key-pair key-pair "gost-keypair" "MyPassword12")
        key-pair2 (crypto-gost.sign/load-key-pair "gost-keypair" "MyPassword12")]
    )
```

### Encryption

This library provides GOST 28147-89 CFB encryption mode only which is most secured mode.
Here is example for encrypt/decrypt operations.

```clojure

  ;; define plain text
  (def m3 "Suppose the original message has length = 50 bytes")

  ;; generate secert key from password
  (def k (crypto-gost.encrypt/gen-secret-key-from-pwd "MyPassword12"))

  ;; this fn generates random iv 
  ;; iv must be random during every encryption of plain text
  ;; encrypted iv should be passed with encrypted text
  (defn gen-iv
    "generate random iv for GOST 28147-89"
    []
    (let [iv-array (byte-array 8)]
      (.nextBytes (SecureRandom.) iv-array)
      iv-array))

  (crypto-gost.common/bytes-to-hex (gen-iv))
  ;; => "933c5e712fa250b6"

  ;; for this example define iv as constant.
  ;; never do it in prod. iv must be random 
  ;; convert hex to bytes array
  (def iv (crypto-gost.common/hex-to-bytes "933c5e712fa250b6"))

  ;;encrypt and decrypt data
  (let [plain-text (.getBytes m3)
        enc-data (crypto-gost.encrypt/encrypt-cfb k iv plain-text)
        dec-data (crypto-gost.encrypt/decrypt-cfb k iv enc-data)]
    (= m3 (String. dec-data)))
    
```
Also you can encrypt/decrypt streaming input and output (File, Socket, URL etc.)

```clojure
;; suppose m3.txt file has a message m3
(let [plain-file "m3.txt"
        enc-file "m3.enc"
        dec-file "m3.dec"]
    (crypto-gost.encrypt/encrypt-stream-cfb k iv plain-file enc-file)
    (crypto-gost.encrypt/decrypt-stream-cfb k iv enc-file dec-file)
    (= (slurp plain-file) (slurp dec-file)))
```
GOST has mac defense against encrypted text modification. Mac is calculated for plain text.
Just send encrypted mac 4 bytes vector with encrypted text and verify mac with decrypted plain text.
If macs are not the same then encrypted text was tampered.
Here is example of mac generation:

```clojure
(let [plain-text (.getBytes m3)
      mac (crypto-gost.encrypt/mac-gen k plain-text)]
    mac)
```


### Digest/HMAC



### Sign/Verify



## License

Copyright © 2017 Mike Ananev

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
