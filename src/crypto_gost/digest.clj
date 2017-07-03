(ns crypto-gost.digest
  (:gen-class)
  (:require [clojure.java.io :as io :refer [input-stream]])
  (:import java.security.Security
           [org.bouncycastle.crypto.digests GOST3411_2012_256Digest GOST3411_2012_512Digest GOST3411Digest]
           org.bouncycastle.jce.provider.BouncyCastleProvider
           org.bouncycastle.util.encoders.Hex))

(defn- digest-class
  "return initilized GOST digest class based on given algo-type"
  [algo-type]
  (case algo-type
    :3411-94 (GOST3411Digest.)
    :3411-2012-256 (GOST3411_2012_256Digest.)
    :3411-2012-512 (GOST3411_2012_512Digest.)
    (GOST3411_2012_256Digest.)))


(defn digest
  "calculate GOST digest from given byte array.
  return digest as bytes array"
  [algo-type bytes-data]
  (Security/addProvider (BouncyCastleProvider.))
  (let [digest (digest-class algo-type)
        _ (.update digest bytes-data 0 (alength bytes-data))
        digest-buffer (byte-array (.getDigestSize digest))
        _ (.doFinal digest digest-buffer 0)]
    digest-buffer))


(defn digest-str
  "calculate GOST digest from string.
  return digest as hex String"
  [algo-type s]
  (Hex/toHexString (digest algo-type (.getBytes s))))


(defn digest-stream
  "calculate GOST digest for given streaming input.
  As input may be:  File, URI, URL, Socket, byte array, or filename as String  which  will be coerced to BufferedInputStream and auto closed after.
  return digest as byte array."
  [algo-type input]
  (Security/addProvider (BouncyCastleProvider.))
  (with-open [in (input-stream input)]
    (let [buf (byte-array 1024)
          digest (digest-class algo-type)
          hash-buffer (byte-array (.getDigestSize digest))]
      (loop [n (.read in buf)]
        (if (<= n 0)
          (do (.doFinal digest hash-buffer 0) hash-buffer)
          (recur (do (.update digest buf 0 n) (.read in buf))))))))



