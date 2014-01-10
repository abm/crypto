(ns crypto.core-test
  (:use midje.sweet)
  (:require [crypto.core :refer :all]))

(fact
 "converting string to hex"
 (hexify "") => []
 (hexify "Man") => [77 97 110])

(fact
 "int to byte sized bit string"
 (bit-str 77) => "01001101"
 (bit-str 97) => "01100001"
 (bit-str 110) => "01101110")

;; (fact
;;  "convert byte seq to 24 bit partitions"
;;  (p24 [] => 0)
;;  (p24 [77] => 2r1001101)
;;  (p24 [77 97 110]) => 2r 01001101 01100001 01101110)

;; (fact
;;  "encode hex sequences to Base64"
;;  (b64 "") => ""
;;  (b64 "f") => "Zg=="
;;  (b64 "fo") => "Zm8="
;;  (b64 "foo") => "Zm9v"
;;  (b64 "foob") => "Zm9vYg=="
;;  (b64 "fooba") => "Zm9vYmE="
;;  (b64 "foobar") => "Zm9vYmFy")
