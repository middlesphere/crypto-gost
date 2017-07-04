(ns crypto-gost.digest-test
  (:require [clojure.test :as t :refer [deftest is]]
            [crypto-gost.common :refer [bytes-to-hex]]
            [crypto-gost.digest :as digest]))

(def m1 "")
(def m2 "The quick brown fox jumps over the lazy dog")
(def m3 "Suppose the original message has length = 50 bytes")
(def m4 "This is message, length=32 bytes")


;; Etalon digests 3411-94 with CryptoPro params https://en.wikipedia.org/wiki/GOST_(hash_function)
(def m1-3411-94 "981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0")
(def m2-3411-94 "9004294a361a508c586fe53d1f1b02746765e71b765472786e4770d565830a76")
(def m3-3411-94 "c3730c5cbccacf915ac292676f21e8bd4ef75331d9405e5f1a61dc3130a65011")
(def m4-3411-94 "2cefc2f7b7bdc514e18ea57fa74ff357e7fa17d652c75f69cb1be7893ede48eb")

;; Etalon digests 3411-2012-256 with CryptoPro params https://en.wikipedia.org/wiki/Streebog
;; also http://www.netlab.linkpc.net/download/software/SDK/core/include/gost3411-2012.h
(def m1-3411-12-256 "3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb")
(def m2-3411-12-256 "3e7dea7f2384b6c5a3d0e24aaa29c05e89ddd762145030ec22c71a6db8b2c1f4")
(def m3-3411-12-256 "a3ed85322e1a1479b605a752b1d487fd138863aa1ea67a91e157aa53fce796f3")
(def m4-3411-12-256 "6fa8592b1cd28ca72d87e7d413d8b3de31077098bed3818d98f6f79bac5cc645")

(def m1-3411-12-512 "8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a")
(def m2-3411-12-512 "d2b793a0bb6cb5904828b5b6dcfb443bb8f33efc06ad09368878ae4cdc8245b97e60802469bed1e7c21a64ff0b179a6a1e0bb74d92965450a0adab69162c00fe")
(def m3-3411-12-512 "275557a47dcfcb8235ff029b74837f0441efe41aed12c207313e83b27abd1e6a9d892713bc30a16bf947d46a59bbbb3a33ee33385391c73675e7d0c360213540")
(def m4-3411-12-512 "eeb2c35b760457d290022fc060e29500122ccdbd73b834ec04048d6de75e942fc52df86fa0ddddfce882b8dbda573ffba0232903c4c057b76624962809c184bf")

;; hmac constants (not from standard)
(def const-seed "012346789abcdef")
(def m3-hmac-3411-94 "3a05abb54a68dc8d22bb4b7d19999ebc10f2fbbcfe0167ceb0ba8fbb80e0250f")
(def m3-hmac-3411-12-256 "a8b619bc2800e5875db0c8a5aeee636acad5fa628e729b1c8f0c4f600b729f07")
(def m3-hmac-3411-12-512 "d6d4feaaf80fbcd54b7e0322492898efaee597c25b8a414ed8ebda4f380cf0d138dc13ab7d6b3451f6e67822198b5cf6dfd5bb392aba03b7521d51cd725c91bd")



(deftest gost-3411-94-test
  (let [r1 (digest/digest-str :3411-94 m1)
        r2 (digest/digest-str :3411-94 m2)
        r3 (digest/digest-str :3411-94 m3)
        r4 (digest/digest-str :3411-94 m4)]
    (is (= m1-3411-94 r1))
    (is (= m2-3411-94 r2))
    (is (= m3-3411-94 r3))
    (is (= m4-3411-94 r4))))


(deftest gost-3411-2012-256-test
  (let [r1 (digest/digest-str :3411-2012-256 m1)
        r2 (digest/digest-str :3411-2012-256 m2)
        r3 (digest/digest-str :3411-2012-256 m3)
        r4 (digest/digest-str :3411-2012-256 m4)]
    (is (= m1-3411-12-256 r1))
    (is (= m2-3411-12-256 r2))
    (is (= m3-3411-12-256 r3))
    (is (= m4-3411-12-256 r4))))


(deftest gost-3411-2012-512-test
  (let [r1 (digest/digest-str :3411-2012-512 m1)
        r2 (digest/digest-str :3411-2012-512 m2)
        r3 (digest/digest-str :3411-2012-512 m3)
        r4 (digest/digest-str :3411-2012-512 m4)]
    (is (= m1-3411-12-512 r1))
    (is (= m2-3411-12-512 r2))
    (is (= m3-3411-12-512 r3))
    (is (= m4-3411-12-512 r4))))


(deftest gost-3411-all-streams
  (let [r1 (bytes-to-hex (digest/digest-stream :3411-94 "test/data/m1.txt"))
        r2 (bytes-to-hex (digest/digest-stream :3411-94 "test/data/m2.txt"))
        r3 (bytes-to-hex (digest/digest-stream :3411-94 "test/data/m3.txt"))
        r4 (bytes-to-hex (digest/digest-stream :3411-94 "test/data/m4.txt"))

        r5 (bytes-to-hex (digest/digest-stream :3411-2012-256 "test/data/m1.txt"))
        r6 (bytes-to-hex (digest/digest-stream :3411-2012-256 "test/data/m2.txt"))
        r7 (bytes-to-hex (digest/digest-stream :3411-2012-256 "test/data/m3.txt"))
        r8 (bytes-to-hex (digest/digest-stream :3411-2012-256 "test/data/m4.txt"))

        r9 (bytes-to-hex (digest/digest-stream :3411-2012-512 "test/data/m1.txt"))
        r10 (bytes-to-hex (digest/digest-stream :3411-2012-512 "test/data/m2.txt"))
        r11 (bytes-to-hex (digest/digest-stream :3411-2012-512 "test/data/m3.txt"))
        r12 (bytes-to-hex (digest/digest-stream :3411-2012-512 "test/data/m4.txt"))]

    (is (= m1-3411-94 r1))
    (is (= m2-3411-94 r2))
    (is (= m3-3411-94 r3))
    (is (= m4-3411-94 r4))

    (is (= m1-3411-12-256 r5))
    (is (= m2-3411-12-256 r6))
    (is (= m3-3411-12-256 r7))
    (is (= m4-3411-12-256 r8))

    (is (= m1-3411-12-512 r9))
    (is (= m2-3411-12-512 r10))
    (is (= m3-3411-12-512 r11))
    (is (= m4-3411-12-512 r12))))


(deftest hmac-all
  (let [r1 (bytes-to-hex (digest/hmac-stream :3411-94 "test/data/m3.txt" const-seed))
        r2 (bytes-to-hex (digest/hmac-stream :3411-2012-256 "test/data/m3.txt" const-seed))
        r3 (bytes-to-hex (digest/hmac-stream :3411-2012-512 "test/data/m3.txt" const-seed))]

    (is (= r1 m3-hmac-3411-94))
    (is (= r2 m3-hmac-3411-12-256))
    (is (= r3 m3-hmac-3411-12-512))))
