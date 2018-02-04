(ns crypto-gost.sign-test
  (:require [clojure.test :refer [deftest is]]
            [crypto-gost.sign :as sut])
  (:import java.io.File))

(def m3 "Suppose the original message has length = 50 bytes")

(deftest gost-3410
  (let [kp       (sut/gen-keypair)
        filename "keys-3410"
        pwd      "pwd123"
        _        (sut/save-key-pair kp filename pwd)
        kp2      (sut/load-key-pair filename pwd)
        hash     (crypto-gost.digest/digest :3411-94 (.getBytes m3))
        sign     (sut/sign hash (.getPrivate kp))
        v1       (sut/verify hash (.getPublic kp) sign)
        v2       (sut/verify hash (.getPublic kp2) sign)
        sign2    (sut/sign hash (.getPrivate kp2))
        v3       (sut/verify hash (.getPublic kp) sign2)]
    (is (= true v1))
    (is (= true v2))
    (is (= true v3))
    (.delete (File. (str filename ".priv")))
    (.delete (File. (str filename ".pub")))))


(deftest gost-2012
  (let [kp       (sut/gen-keypair-2012)
        filename "keys-3410-2012"
        pwd      "pwd123"
        _        (sut/save-key-pair kp filename pwd)
        kp2      (sut/load-key-pair-2012 filename pwd)
        hash     (crypto-gost.digest/digest :3411-2012-512 (.getBytes m3))
        sign     (sut/sign-2012 hash (.getPrivate kp))
        v1       (sut/verify-2012 hash (.getPublic kp) sign)
        v2       (sut/verify-2012 hash (.getPublic kp2) sign)
        sign2    (sut/sign-2012 hash (.getPrivate kp2))
        v3       (sut/verify-2012 hash (.getPublic kp) sign2)
        ]
    (is (= true v1))
    (is (= true v2))
    (is (= true v3))
    (.delete (File. (str filename ".priv")))
    (.delete (File. (str filename ".pub")))))
