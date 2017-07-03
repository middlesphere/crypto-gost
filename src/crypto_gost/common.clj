(ns crypto-gost.common
  (:gen-class)
  (:import javax.crypto.Cipher
           org.bouncycastle.util.encoders.Hex))

(defn jce-unlimited?
  "check if JCA/JCE has unlimited cryptography strength.
  call this once before use of any crypto functions."
  []
  (if (= 2147483647 (Cipher/getMaxAllowedKeyLength "AES"))
    true
    false))


(defn bytes-to-hex
  "convert bytes array to hex String."
  [b]
  (Hex/toHexString b))


(defn hex-to-bytes
  "convert hex String to bytes array"
  [s]
  (Hex/decode s))


