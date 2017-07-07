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
Note: if you use OracleJDK then  Bouncycastle jar should be in class path as separate library, not in uberjar, cause its content is signed.
Use OpenJDK to avoid problems with uberjar and Bouncycastle. 

Then require necessary namespaces:
```clojure
(:require   crypto-gost.common
            crypto-gost.encrypt
            crypto-gost.digest
            crypto-gost.sign)

```

### Key generation

To generate secret key for GOST 28147-89 using Java SecureRandom use crypto-gost.encrypt/gen-secret-key:

```clojure
(let [secret-key (crypto-gost.encrypt/gen-secret-key)
        key-hex (crypto-gost.common/bytes-to-hex secret-key)]
    (println "genarated secret key:" key-hex))    
```
This code produces output: ```genarated secret key: f29389a2904d736917140a4a748be5077eafd251c44e097d9c3aeb2c0b3f2cfc```


### Encryption


### Digest/HMAC



### Sign/Verify



## License

Copyright © 2017 Mike Ananev

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
