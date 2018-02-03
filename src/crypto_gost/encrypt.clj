(ns crypto-gost.encrypt
  (:gen-class)
  (:require [clojure.java.io :refer [input-stream output-stream]]
            [crypto-gost.common :as common])
  (:import [java.io ByteArrayInputStream ByteArrayOutputStream DataInputStream]
           [java.security Key SecureRandom Security]
           [javax.crypto Cipher CipherInputStream CipherOutputStream KeyGenerator Mac]
           [javax.crypto.spec IvParameterSpec SecretKeySpec]
           org.bouncycastle.crypto.digests.GOST3411Digest
           org.bouncycastle.crypto.generators.PKCS12ParametersGenerator
           org.bouncycastle.crypto.params.KeyParameter
           org.bouncycastle.crypto.PBEParametersGenerator
           org.bouncycastle.jce.provider.BouncyCastleProvider))


(defn encrypt-3412-cfb
  "encrypt plain-data as bytes array in CFB mode using given key (32 bytes array) and iv (16 bytes array).
  Encryption algorithm is GOST 3412-2015.
  return encrypted text as bytes array."
  [k iv plain-data]
  (Security/addProvider (BouncyCastleProvider.))
  (let [enc-key (SecretKeySpec. k "GOST3412-2015")
        cipher  (Cipher/getInstance "GOST3412-2015/CFB8/NoPadding" "BC")
        _       (.init cipher Cipher/ENCRYPT_MODE enc-key (IvParameterSpec. iv))
        bOut    (ByteArrayOutputStream.)
        cOut    (CipherOutputStream. bOut cipher)
        _       (.write cOut plain-data 0 (alength plain-data))
        _       (.close cOut)]
    (.toByteArray bOut)))


(defn decrypt-3412-cfb
  "decrypt encrypted-data as bytes array in CFB mode using given key (32 bytes array) and iv (16 bytes array).
  Decryption algorithm is GOST 3412-2015.
  return decrypted plain text as bytes array."
  [k iv encrypted-data]
  (Security/addProvider (BouncyCastleProvider.))
  (let [dec-key              (SecretKeySpec. k "GOST3412-2015")
        cipher               (Cipher/getInstance "GOST3412-2015/CFB8/NoPadding" "BC")
        decrypted-data-array (byte-array (alength encrypted-data))
        _                    (.init cipher Cipher/DECRYPT_MODE dec-key (IvParameterSpec. iv))
        bIn                  (ByteArrayInputStream. encrypted-data)
        cIn                  (CipherInputStream. bIn cipher)
        dIn                  (DataInputStream. cIn)
        _                    (.readFully dIn decrypted-data-array)
        _                    (.close bIn)]
    decrypted-data-array))


(defn encrypt-cfb
  "encrypt plain-data as bytes array in CFB mode using given key (32 bytes array) and iv (8 bytes array).
  Encryption algorithm is GOST 28147-89.
  return encrypted text as bytes array."
  [k iv plain-data]
  (Security/addProvider (BouncyCastleProvider.))
  (let [enc-key (SecretKeySpec. k "GOST28147")
        cipher  (Cipher/getInstance "GOST28147/CFB8/NoPadding" "BC")
        _       (.init cipher Cipher/ENCRYPT_MODE enc-key (IvParameterSpec. iv))
        bOut    (ByteArrayOutputStream.)
        cOut    (CipherOutputStream. bOut cipher)
        _       (.write cOut plain-data 0 (alength plain-data))
        _       (.close cOut)]
    (.toByteArray bOut)))


(defn decrypt-cfb
  "decrypt encrypted-data as bytes array in CFB mode using given key (32 bytes array) and iv (8 bytes array).
  Decryption algorithm is GOST 28147-89.
  return decrypted plain text as bytes array."
  [k iv encrypted-data]
  (Security/addProvider (BouncyCastleProvider.))
  (let [dec-key              (SecretKeySpec. k "GOST28147")
        cipher               (Cipher/getInstance "GOST28147/CFB8/NoPadding" "BC")
        decrypted-data-array (byte-array (alength encrypted-data))
        _                    (.init cipher Cipher/DECRYPT_MODE dec-key (IvParameterSpec. iv))
        bIn                  (ByteArrayInputStream. encrypted-data)
        cIn                  (CipherInputStream. bIn cipher)
        dIn                  (DataInputStream. cIn)
        _                    (.readFully dIn decrypted-data-array)
        _                    (.close bIn)]
    decrypted-data-array))


(defn encrypt-3412-stream-cfb
  "encrypt given streaming input in CFB mode and write encrypted data to streaming output.
  As input may be:  File, URI, URL, Socket, byte array, or filename as String  which  will be
  coerced to BufferedInputStream and auto closed after.
  output should be  File, URI, URL, Socket, byte array, or filename as String  which  will be
  coerced to BuffereOutputStream and auto closed after.
  Encryption algorithm is GOST 3412-2015.
  iv must be 16 bytes array.
  return nil."
  [k iv input output]
  (Security/addProvider (BouncyCastleProvider.))
  (with-open [in  (input-stream input)
              out (output-stream output)]
    (let [enc-key   (SecretKeySpec. k "GOST3412-2015")
          cipher    (Cipher/getInstance "GOST3412-2015/CFB8/NoPadding" "BC")
          _         (.init cipher Cipher/ENCRYPT_MODE enc-key (IvParameterSpec. iv))
          cOut      (CipherOutputStream. out cipher)
          plain-buf (byte-array 1024)]
      (loop [n (.read in plain-buf)]
        (if (<= n 0)
          (do (.close cOut))
          (recur (do (.write cOut plain-buf 0 n) (.read in plain-buf))))))))


(defn decrypt-3412-stream-cfb
  "decrypt given streaming input in CFB mode and write plain data to streaming output.
  As input may be:  File, URI, URL, Socket, byte array, or filename as String  which  will be
  coerced to BufferedInputStream and auto closed after.
  output should be  File, URI, URL, Socket, byte array, or filename as String  which  will be
  coerced to BuffereOutputStream and auto closed after.
  Decryption algorithm is GOST 3412-2015.
  iv must be 16 bytes array.
  return nil."
  [k iv input output]
  (Security/addProvider (BouncyCastleProvider.))
  (with-open [in  (input-stream input)
              out (output-stream output)]
    (let [dec-key   (SecretKeySpec. k "GOST3412-2015")
          cipher    (Cipher/getInstance "GOST3412-2015/CFB8/NoPadding" "BC")
          _         (.init cipher Cipher/DECRYPT_MODE dec-key (IvParameterSpec. iv))
          cIn       (CipherInputStream. in cipher)
          dIn       (DataInputStream. cIn)
          plain-buf (byte-array 1024)]
      (loop [n (.read dIn plain-buf)]
        (if (<= n 0)
          (do (.close dIn))
          (recur (do (.write out plain-buf 0 n) (.read dIn plain-buf))))))))


(defn encrypt-stream-cfb
  "encrypt given streaming input in CFB mode and write encrypted data to streaming output.
  As input may be:  File, URI, URL, Socket, byte array, or filename as String  which  will be
  coerced to BufferedInputStream and auto closed after.
  output should be  File, URI, URL, Socket, byte array, or filename as String  which  will be
  coerced to BuffereOutputStream and auto closed after.
  Encryption algorithm is GOST 28147-89.
  iv must be 8 bytes array.
  return nil."
  [k iv input output]
  (Security/addProvider (BouncyCastleProvider.))
  (with-open [in  (input-stream input)
              out (output-stream output)]
    (let [enc-key   (SecretKeySpec. k "GOST28147")
          cipher    (Cipher/getInstance "GOST28147/CFB8/NoPadding" "BC")
          _         (.init cipher Cipher/ENCRYPT_MODE enc-key (IvParameterSpec. iv))
          cOut      (CipherOutputStream. out cipher)
          plain-buf (byte-array 1024)]
      (loop [n (.read in plain-buf)]
        (if (<= n 0)
          (do (.close cOut))
          (recur (do (.write cOut plain-buf 0 n) (.read in plain-buf))))))))


(defn decrypt-stream-cfb
  "decrypt given streaming input in CFB mode and write plain data to streaming output.
  As input may be:  File, URI, URL, Socket, byte array, or filename as String  which  will be
  coerced to BufferedInputStream and auto closed after.
  output should be  File, URI, URL, Socket, byte array, or filename as String  which  will be
  coerced to BuffereOutputStream and auto closed after.
  Decryption algorithm is GOST 28147-89.
  iv must be 8 bytes array.
  return nil."
  [k iv input output]
  (Security/addProvider (BouncyCastleProvider.))
  (with-open [in  (input-stream input)
              out (output-stream output)]
    (let [dec-key   (SecretKeySpec. k "GOST28147")
          cipher    (Cipher/getInstance "GOST28147/CFB8/NoPadding" "BC")
          _         (.init cipher Cipher/DECRYPT_MODE dec-key (IvParameterSpec. iv))
          cIn       (CipherInputStream. in cipher)
          dIn       (DataInputStream. cIn)
          plain-buf (byte-array 1024)]
      (loop [n (.read dIn plain-buf)]
        (if (<= n 0)
          (do (.close dIn))
          (recur (do (.write out plain-buf 0 n) (.read dIn plain-buf))))))))



(defn encrypt-str-cfb
  "encrypt String  in CFB mode using given key (32 bytes array) and iv (8 bytes array).
  Encryption algorithm is GOST 28147-89.
  return encrypted text as String in hex."
  [k iv ^String s]
  (let [e (encrypt-cfb k iv (.getBytes s))]
    (common/bytes-to-hex e)))



(defn decrypt-str-cfb
  "decrypt ^String enc-text-hex in CFB mode using given key (32 bytes array) and iv (8 bytes array).
  Decryption algorithm is GOST 28147-89.
  return plain text as String."
  [k iv ^String enc-text-hex]
  (let [d (decrypt-cfb k iv (common/hex-to-bytes enc-text-hex))]
    (String. d)))


(defn encrypt-3412-str-cfb
  "encrypt String  in CFB mode using given key (32 bytes array) and iv (16 bytes array).
  Encryption algorithm is GOST 3412-2015.
  return encrypted text as String in hex."
  [k iv ^String s]
  (let [e (encrypt-3412-cfb k iv (.getBytes s))]
    (common/bytes-to-hex e)))



(defn decrypt-3412-str-cfb
  "decrypt ^String enc-text-hex in CFB mode using given key (32 bytes array) and iv (16 bytes array).
  Decryption algorithm is GOST 3412-2015.
  return plain text as String."
  [k iv ^String enc-text-hex]
  (let [d (decrypt-3412-cfb k iv (common/hex-to-bytes enc-text-hex))]
    (String. d)))



(defn mac-gen
  "generate MAC GOST 28147-89 for plain-data (bytes array) using given key (32 bytes array)
  return 4 bytes array with MAC."
  [k plain-data]
  (Security/addProvider (BouncyCastleProvider.))
  (let [mac     (Mac/getInstance "GOST28147MAC" "BC")
        key     (SecretKeySpec. k "GOST28147")
        _       (.init mac key)
        mac-buf (byte-array 4)]
    (.update mac plain-data 0 (alength plain-data))
    (.doFinal mac mac-buf 0)
    mac-buf))


(defn mac-3412-gen
  "generate MAC GOST 3412-2015 for plain-data (bytes array) using given key (32 bytes array)
  return 16 bytes array with MAC."
  [k plain-data]
  (Security/addProvider (BouncyCastleProvider.))
  (let [mac     (Mac/getInstance "GOST3412MAC" "BC")
        key     (SecretKeySpec. k "GOST3412-2015")
        _       (.init mac key)
        mac-buf (byte-array 16)]
    (.update mac plain-data 0 (alength plain-data))
    (.doFinal mac mac-buf 0)
    mac-buf))

(defn gen-secret-key
  "generate secret key for GOST 28147-89 using SecureRandom class
  return 32 bytes array of secret key"
  []
  (Security/addProvider (BouncyCastleProvider.))
  (let [key-gen   (KeyGenerator/getInstance "GOST28147" "BC")
        _         (.init key-gen (SecureRandom.))
        ^Key key  (.generateKey key-gen)
        bytes-key (.getEncoded key)]
    bytes-key))



(defn gen-secret-key-from-pwd
  "generate secret key from password using PKCS12
  return bytes array 32 bytes with secret key."
  [^String password]
  (Security/addProvider (BouncyCastleProvider.))
  (let [salt       (.getBytes "2017-07-07-14-59-23")
        iter-count 2048
        pass-key   (PBEParametersGenerator/PKCS12PasswordToBytes (.toCharArray password))
        pbe-gen    (PKCS12ParametersGenerator. (GOST3411Digest.))
        _          (.init pbe-gen pass-key salt iter-count)
        params     (.generateDerivedParameters pbe-gen 256)
        ^Key key   (SecretKeySpec. (-> ^KeyParameter params .getKey) "GOST28147")
        bytes-key  (.getEncoded key)]
    bytes-key))






