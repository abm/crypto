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

(fact
 (b64-indexes []) => []
 (b64-indexes [3]) => [0 48]
 (b64-indexes [3 217]) => [0 61 36]
 (b64-indexes [77 97 110]) => [19 22 5 46])

(fact
 "encode hex sequences to Base64"
 (b64s "") => ""
 (b64s "f") => "Zg=="
 (b64s "fo") => "Zm8="
 (b64s "foo") => "Zm9v"
 (b64s "foob") => "Zm9vYg=="
 (b64s "fooba") => "Zm9vYmE="
 (b64s "foobar") => "Zm9vYmFy")
