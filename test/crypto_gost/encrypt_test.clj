(ns crypto-gost.encrypt-test
  (:require [clojure.test :as t :refer [deftest is]]
            [crypto-gost.encrypt :as sut]
            [crypto-gost.common :as common])
  (:import java.io.File))

(def m3 "Suppose the original message has length = 50 bytes")
(def k (.getBytes "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
(def iv (.getBytes "abcdefgh"))


(deftest gost-28147-cfb
  (let [plain-text (.getBytes m3)
        enc-data (sut/encrypt-cfb k iv plain-text)
        dec-data (sut/decrypt-cfb k iv enc-data)]
    (is (= m3 (String. dec-data)))))


(deftest gost-28147-stream-cfb
  (let [plain-file "test/data/m3.txt"
        enc-file "test/data/m3.enc"
        dec-file "test/data/m3.dec"]
    (sut/encrypt-stream-cfb k iv plain-file enc-file)
    (sut/decrypt-stream-cfb k iv enc-file dec-file)
    (is (= (slurp plain-file) (slurp dec-file)))
    (.delete (File. enc-file))
    (.delete (File. dec-file))))


(deftest gost-28147-str-cfb
  (let [plain-text m3
        enc-data (sut/encrypt-str-cfb k iv plain-text)
        dec-data (sut/decrypt-str-cfb k iv enc-data)]
    (is (= plain-text dec-data))))


(deftest mac
  (let [plain-text (.getBytes m3)
        mac (sut/mac-gen k plain-text)]
    (is (= "d34bd048" (common/bytes-to-hex mac)))))


(deftest gen-secret-key
  (let [k1 (sut/gen-secret-key)
        k2 (sut/gen-secret-key)
        k1-hex (common/bytes-to-hex k1)
        k2-hex (common/bytes-to-hex k2)]
    (is (= 32 (alength k1)))
    (is (= 32 (alength k2)))
    (is (not= k1-hex k2-hex))))

(deftest gen-secret-key-from-pwd
  (let [pwd "hello, world"
        wrong-pwd "hello world"
        etalon-hex "09367bbc879a28ec5d416d9473ea4eff9d893967add7466e366360edeccad25b"
        sec-key (sut/gen-secret-key-from-pwd pwd)
        hex-key (common/bytes-to-hex sec-key)
        wrong-key (sut/gen-secret-key-from-pwd wrong-pwd)
        hex-wrong-key (common/bytes-to-hex wrong-key)]
    (is (= etalon-hex hex-key))
    (is (not= etalon-hex hex-wrong-key))))

