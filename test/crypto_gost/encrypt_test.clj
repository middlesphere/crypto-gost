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
