(ns crypto-gost.encrypt
  (:gen-class)
  (:require [clojure.java.io :refer [input-stream output-stream]]
            [crypto-gost.common :as common])
  (:import [java.io ByteArrayInputStream ByteArrayOutputStream DataInputStream]
           java.security.Security
           [javax.crypto Cipher CipherInputStream CipherOutputStream Mac]
           [javax.crypto.spec IvParameterSpec SecretKeySpec]
           org.bouncycastle.jce.provider.BouncyCastleProvider))

(defn encrypt-cfb
  "encrypt plain-data as bytes array in CFB mode using given key (32 bytes array) and iv (8 bytes array).
  return encrypted text as bytes array."
  [k iv plain-data]
  (Security/addProvider (BouncyCastleProvider.))
  (let [enc-key (SecretKeySpec. k "GOST28147")
        cipher (Cipher/getInstance "GOST28147/CFB8/NoPadding" "BC")
        _ (.init cipher Cipher/ENCRYPT_MODE enc-key (IvParameterSpec. iv))
        bOut (ByteArrayOutputStream.)
        cOut (CipherOutputStream. bOut cipher)
        _ (.write cOut plain-data 0 (alength plain-data))
        _ (.close cOut)]
    (.toByteArray bOut)))


(defn decrypt-cfb
  "decrypt encrypted-data as bytes array in CFB mode using given key (32 bytes array) and iv (8 bytes array).
  return decrypted plain text as bytes array."
  [k iv encrypted-data]
  (Security/addProvider (BouncyCastleProvider.))
  (let [dec-key (SecretKeySpec. k "GOST28147")
        cipher (Cipher/getInstance "GOST28147/CFB8/NoPadding" "BC")
        decrypted-data-array (byte-array (alength encrypted-data))
        _ (.init cipher Cipher/DECRYPT_MODE dec-key (IvParameterSpec. iv))
        bIn (ByteArrayInputStream. encrypted-data)
        cIn (CipherInputStream. bIn cipher)
        dIn (DataInputStream. cIn)
        _ (.readFully dIn decrypted-data-array)
        _ (.close bIn)]
    decrypted-data-array))


(defn encrypt-stream-cfb
  "encrypt given streaming input in CFB mode and write encrypted data to streaming output.
  As input may be:  File, URI, URL, Socket, byte array, or filename as String  which  will be
  coerced to BufferedInputStream and auto closed after.
  output should be  File, URI, URL, Socket, byte array, or filename as String  which  will be
  coerced to BuffereOutputStream and auto closed after.
  return nil."
  [k iv input output]
  (Security/addProvider (BouncyCastleProvider.))
  (with-open [in (input-stream input)
              out (output-stream output)]
    (let [enc-key (SecretKeySpec. k "GOST28147")
          cipher (Cipher/getInstance "GOST28147/CFB8/NoPadding" "BC")
          _ (.init cipher Cipher/ENCRYPT_MODE enc-key (IvParameterSpec. iv))
          cOut (CipherOutputStream. out cipher)
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
  return nil."
  [k iv input output]
  (Security/addProvider (BouncyCastleProvider.))
  (with-open [in (input-stream input)
              out (output-stream output)]
    (let [dec-key (SecretKeySpec. k "GOST28147")
          cipher (Cipher/getInstance "GOST28147/CFB8/NoPadding" "BC")
          _ (.init cipher Cipher/DECRYPT_MODE dec-key (IvParameterSpec. iv))
          cIn (CipherInputStream. in cipher)
          dIn (DataInputStream. cIn)
          plain-buf (byte-array 1024)]
      (loop [n (.read dIn plain-buf)]
        (if (<= n 0)
          (do (.close dIn))
          (recur (do (.write out plain-buf 0 n) (.read dIn plain-buf))))))))



(defn encrypt-str-cfb
  "encrypt String  in CFB mode using given key (32 bytes array) and iv (8 bytes array).
  return encrypted text as String in hex."
  [k iv ^String s]
  (let [e (encrypt-cfb k iv (.getBytes s))]
    (common/bytes-to-hex e)))



(defn decrypt-str-cfb
  "decrypt ^String enc-text-hex in CFB mode using given key (32 bytes array) and iv (8 bytes array).
  return plain text as String."
  [k iv ^String enc-text-hex]
  (let [d (decrypt-cfb k iv (common/hex-to-bytes enc-text-hex))]
    (String. d)))


(defn mac-gen
  "generate MAC GOST 28147-89 for plain-data (bytes array) using given key (32 bytes array)
  return 4 bytes array with MAC."
  [k plain-data]
  (Security/addProvider (BouncyCastleProvider.))
  (let [mac (Mac/getInstance "GOST28147MAC" "BC")
        key (SecretKeySpec. k "GOST28147")
        _ (.init mac key)
        mac-buf (byte-array 4)]
    (.update mac plain-data 0 (alength plain-data))
    (.doFinal mac mac-buf 0)
    mac-buf))

 



