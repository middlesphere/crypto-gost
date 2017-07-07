# crypto-gost

A thin Clojure warpper for Bouncycastle library (https://bouncycastle.org) to work with GOST algorithms (Russian security standards).

## Intro

This library provides functions to work with: 
* encryption, mac (imito) using GOST 28147-89,
* digest functions (GOST3411-94/2012 256 and 512 bit), 
* signature (GOST3410-2001)
* key generation (secret, public/private)


## Usage

Add dependencies to your project:
```clojure
:dependencies [[org.bouncycastle/bcprov-jdk15on "1.57"]
               [crypto-gost "0.1"]]
```

### Key generation


### Encryption


### Digest/HMAC



### Sign/Verify



## License

Copyright © 2017 Mike Ananev

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
