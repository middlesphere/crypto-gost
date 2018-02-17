(ns crypto-gost.sign
  (:gen-class)
  (:require [crypto-gost.common :as common]
            crypto-gost.encrypt)
  (:import [java.security KeyFactory KeyPairGenerator PrivateKey PublicKey SecureRandom Security Signature KeyPair]
           [java.security.spec EncodedKeySpec PKCS8EncodedKeySpec X509EncodedKeySpec]
           [org.bouncycastle.crypto.signers ECGOST3410_2012Signer]
           [org.bouncycastle.jcajce.provider.asymmetric.util ECUtil]
           [org.bouncycastle.crypto.params ParametersWithRandom]
           [org.bouncycastle.jce.interfaces ECPrivateKey ECPublicKey]
           org.bouncycastle.jce.ECGOST3410NamedCurveTable
           org.bouncycastle.jce.provider.BouncyCastleProvider
           org.bouncycastle.jce.spec.ECNamedCurveParameterSpec))


(defn gen-keypair-2012
  "Generate GOST3410-2012 keypair using Tc26-Gost-3410-12-512-paramSetA params by default.
  Availbable params: Tc26-Gost-3410-12-256-paramSetA, Tc26-Gost-3410-12-512-paramSetA, Tc26-Gost-3410-12-512-paramSetA,
  Tc26-Gost-3410-12-512-paramSetB, Tc26-Gost-3410-12-512-paramSetC  
  return ^KeyPair object."
  ([] (gen-keypair-2012 "Tc26-Gost-3410-12-512-paramSetA"))
  ([^String ec-params]
   (Security/addProvider (BouncyCastleProvider.))
   (let [^ECNamedCurveParameterSpec named-curve-param-spec (ECGOST3410NamedCurveTable/getParameterSpec ec-params) 
         ^KeyPairGenerator keypair-generator               (KeyPairGenerator/getInstance "ECGOST3410-2012" "BC")
         rand-engine                                       (SecureRandom.)
         _                                                 (.initialize keypair-generator named-curve-param-spec rand-engine)
         keypair                                           (.generateKeyPair keypair-generator)]
     keypair)))


(defn gen-keypair
  "Generate GOST3410-2001 keypair using CryptoPro-A params by default.
  Availbable params GostR3410-2001-CryptoPro-XchB GostR3410-2001-CryptoPro-XchA
  GostR3410-2001-CryptoPro-C GostR3410-2001-CryptoPro-B GostR3410-2001-CryptoPro-A
  return ^KeyPair object."
  ([] (gen-keypair "GostR3410-2001-CryptoPro-A"))
  ([^String ec-params]
   (Security/addProvider (BouncyCastleProvider.))
   (let [^ECNamedCurveParameterSpec named-curve-param-spec (ECGOST3410NamedCurveTable/getParameterSpec ec-params) 
         ^KeyPairGenerator keypair-generator               (KeyPairGenerator/getInstance "ECGOST3410" "BC")
         rand-engine                                       (SecureRandom.)
         _                                                 (.initialize keypair-generator named-curve-param-spec rand-engine)
         keypair                                           (.generateKeyPair keypair-generator)]
     keypair)))



(defn sign-2012
  "generate signature GOST 3410-2012 from a given hash using given private key.
  return byte[64] or byte[128] array of signature depending on private key length."
  [^bytes hash-bytes ^ECPrivateKey private-key]
  (Security/addProvider (BouncyCastleProvider.))
  (let [key-length        (.bitLength (.getN (.getParameters private-key)))
        sign-engine       (if (= 512 key-length)
                            (Signature/getInstance "ECGOST3410-2012-512")
                            (Signature/getInstance "ECGOST3410-2012-256"))
        rand-engine       (SecureRandom.)
        _                 (.initSign sign-engine private-key rand-engine)
        _                 (.update sign-engine hash-bytes 0 (alength hash-bytes))
        sign-result-bytes (.sign sign-engine)]
    sign-result-bytes))


(defn sign
  "generate signature GOST 3410-2001 from a given hash using given private key.
  return byte[64] array of signature"
  [^bytes hash-bytes ^PrivateKey private-key]
  (Security/addProvider (BouncyCastleProvider.))
  (let [sign-engine       (Signature/getInstance "GOST3411withECGOST3410")
        rand-engine       (SecureRandom.)
        _                 (.initSign sign-engine private-key rand-engine)
        _                 (.update sign-engine hash-bytes 0 (alength hash-bytes))
        sign-result-bytes (.sign sign-engine)]
    sign-result-bytes))


(defn verify-2012
  "verify (bytes array) sign-bytes of GOST 3410-2012 signature using given hash value (bytes array) and public key.
  return: true - signature is correct, false - signature is not correct."
  [^bytes hash-bytes ^ECPublicKey public-key sign-bytes]
  (Security/addProvider (BouncyCastleProvider.))
  (let [key-length  (.bitLength (.getN (.getParameters public-key)))
        sign-engine (if (= 512 key-length)
                      (Signature/getInstance "ECGOST3410-2012-512")
                      (Signature/getInstance "ECGOST3410-2012-256"))
        _           (.initVerify sign-engine public-key)
        _           (.update sign-engine hash-bytes 0 (alength hash-bytes))
        result      (.verify sign-engine sign-bytes)]
    result))


(defn verify
  "verify (bytes array) sign-bytes of GOST 3410-2001 signature using given hash value (bytes array) and public key.
  return: true - signature is correct, false - signature is not correct."
  [^bytes hash-bytes ^PublicKey public-key sign-bytes]
  (Security/addProvider (BouncyCastleProvider.))
  (let [sign-engine (Signature/getInstance "GOST3411withECGOST3410")
        _           (.initVerify sign-engine public-key)
        _           (.update sign-engine hash-bytes 0 (alength hash-bytes))
        result      (.verify sign-engine sign-bytes)]
    result))



(defn public-from-hex
  "return ^PublicKey object for GOST 3410-2001 derived from its hex string representation."
  [^String public-hex]
  (Security/addProvider (BouncyCastleProvider.))
  (let [key-bytes (common/hex-to-bytes public-hex)
        ^EncodedKeySpec public-key-spec (X509EncodedKeySpec. key-bytes)
        ^KeyFactory factory (KeyFactory/getInstance "ECGOST3410" "BC")
        ^PublicKey public-key (.generatePublic factory public-key-spec)]
    public-key))



(defn save-private-key
  "save a private key GOST 3410-2001 in file
  private key will be encrypted with HMAC.
  return nil"
  [^PrivateKey private-key
   ^String filename
   ^String password]
  (let [secret-key (crypto-gost.encrypt/gen-secret-key-from-pwd password)
        private-key-bytes (.getEncoded private-key)
        enc-private-key (crypto-gost.encrypt/encrypt-cfb secret-key (.getBytes "a123456b") private-key-bytes)
        hmac (crypto-gost.digest/hmac :3411-94 enc-private-key password)
        encrypted-key-hex (common/bytes-to-hex enc-private-key)
        hmac-hex (common/bytes-to-hex hmac)
        file-content (str {:private-key encrypted-key-hex :hmac hmac-hex})]
    (spit filename file-content)))



(defn save-public-key
  "save a public key GOST 3410-2001 in file. Public key will be protected with HMAC.
   return nil."
  [^PublicKey public-key
   ^String filename
   ^String password]
  (let [public-key-bytes (.getEncoded public-key)
        public-hex       (common/bytes-to-hex public-key-bytes)
        hmac             (crypto-gost.digest/hmac :3411-94 public-key-bytes password)
        hmac-hex         (common/bytes-to-hex hmac)
        file-content     (str {:public-key public-hex :hmac hmac-hex})]
    (spit filename file-content)))


(defn load-private-key-2012
  "load a private key GOST 3410-2012 from file
  private key HMAC will be verified.
  return ^PrivateKey object if success or nil if key is tampered."
  [^String filename
   ^String password]
  (let [key-struct      (clojure.edn/read-string (slurp filename))
        secret-key      (crypto-gost.encrypt/gen-secret-key-from-pwd password)
        enc-private-key (common/hex-to-bytes (:private-key key-struct))
        new-hmac-hex    (common/bytes-to-hex (crypto-gost.digest/hmac :3411-94 enc-private-key password))]
    (when (= new-hmac-hex (:hmac key-struct))
      (let [decrypted-private-key            (crypto-gost.encrypt/decrypt-cfb secret-key (.getBytes "a123456b") enc-private-key)
            ^EncodedKeySpec private-key-spec (PKCS8EncodedKeySpec. decrypted-private-key)
            ^KeyFactory factory              (KeyFactory/getInstance "ECGOST3410-2012" "BC")
            ^PrivateKey private-key          (.generatePrivate factory private-key-spec)]
        private-key))))

(defn load-private-key
  "load a private key GOST 3410-2001 from file
  private key HMAC will be verified.
  return ^PrivateKey object if success or nil if key is tampered."
  [^String filename
   ^String password]
  (let [key-struct      (clojure.edn/read-string (slurp filename))
        secret-key      (crypto-gost.encrypt/gen-secret-key-from-pwd password)
        enc-private-key (common/hex-to-bytes (:private-key key-struct))
        new-hmac-hex    (common/bytes-to-hex (crypto-gost.digest/hmac :3411-94 enc-private-key password))]
    (when (= new-hmac-hex (:hmac key-struct))
      (let [decrypted-private-key            (crypto-gost.encrypt/decrypt-cfb secret-key (.getBytes "a123456b") enc-private-key)
            ^EncodedKeySpec private-key-spec (PKCS8EncodedKeySpec. decrypted-private-key)
            ^KeyFactory factory              (KeyFactory/getInstance "ECGOST3410" "BC")
            ^PrivateKey private-key          (.generatePrivate factory private-key-spec)]
        private-key))))


(defn load-public-key-2012
  "load a public key GOST 3410-2012 from file
  public key HMAC will be verified.
  return ^PublicKey object if success or nil if key is tampered."
  [^String filename
   ^String password]
  (let [key-struct   (clojure.edn/read-string (slurp filename))
        public-key   (common/hex-to-bytes (:public-key key-struct))
        new-hmac-hex (common/bytes-to-hex (crypto-gost.digest/hmac :3411-94 public-key password))]
    (when (= new-hmac-hex (:hmac key-struct))
      (let [^EncodedKeySpec public-key-spec (X509EncodedKeySpec. public-key)
            ^KeyFactory factory             (KeyFactory/getInstance "ECGOST3410-2012" "BC")
            ^PublicKey public-key           (.generatePublic factory public-key-spec)]
        public-key))))

(defn load-public-key
  "load a public key GOST 3410-2001 from file
  public key HMAC will be verified.
  return ^PublicKey object if success or nil if key is tampered."
  [^String filename
   ^String password]
  (let [key-struct   (clojure.edn/read-string (slurp filename))
        public-key   (common/hex-to-bytes (:public-key key-struct))
        new-hmac-hex (common/bytes-to-hex (crypto-gost.digest/hmac :3411-94 public-key password))]
    (when (= new-hmac-hex (:hmac key-struct))
      (let [^EncodedKeySpec public-key-spec (X509EncodedKeySpec. public-key)
            ^KeyFactory factory             (KeyFactory/getInstance "ECGOST3410" "BC")
            ^PublicKey public-key           (.generatePublic factory public-key-spec)]
        public-key))))


(defn save-key-pair
  "save ^KeyPair object to a files. extensions .priv and .pub automatically will be added to filename.
  private key will be encrypted and protected with hmac.
  public key will be protected with hmac.
  return nil."
  [^KeyPair kp ^String filename ^String password]
  (save-private-key (.getPrivate kp) (str filename ".priv") password)
  (save-public-key (.getPublic kp) (str filename ".pub") password))


(defn load-key-pair-2012
  "load ^KeyPair object from files. Extensions .priv and .pub will be automatically added to filename to load keys from separate files.
  HMAC for all keys will be verified. Private key will be decrypted.
  return ^KeyPair object or nil if errors."
  [^String filename ^String password]
  (let [private-key (load-private-key-2012 (str filename ".priv") password)
        public-key  (load-public-key-2012 (str filename ".pub") password)]
    (KeyPair. public-key private-key)))

(defn load-key-pair
  "load ^KeyPair object from files. Extensions .priv and .pub will be automatically added to filename to load keys from separate files.
  HMAC for all keys will be verified. Private key will be decrypted.
  return ^KeyPair object or nil if errors."
  [^String filename ^String password]
  (let [private-key (load-private-key (str filename ".priv") password)
        public-key  (load-public-key (str filename ".pub") password)]
    (KeyPair. public-key private-key)))


