(ns crypto.core)

(defn hexify
  "string to hex"
  [s]
  (map byte s))

(defn bit-str
  "int to byte sized bit string"
  [i]
  (let [s (Integer/toBinaryString i)]
    (str (apply str (repeat (- 8 (count s)) "0")) s)))

(defn b64-indexes
  "Convert bytes to their Base64 index values"
  [bs]
  (->> bs
   (map bit-str)
   (clojure.string/join)
   (partition 6 6 (repeat \0))
   (map clojure.string/join)
   (map #(Integer/parseInt %1 2))))

(def b64-table ["A" "B" "C" "D" "E" "F" "G" "H" "I" "J" "K" "L" "M" "N" "O" "P" "Q" "R" "S" "T" "U" "V" "W" "X" "Y" "Z" "a" "b" "c" "d" "e" "f" "g" "h" "i" "j" "k" "l" "m" "n" "o" "p" "q" "r" "s" "t" "u" "v" "w" "x" "y" "z" "0" "1" "2" "3" "4" "5" "6" "7" "8" "9" "+" "/"])

(defn b64-lookup
  [indexes]
  (map #(nth b64-table %1) indexes))

(defn b64-pad
  [cs]
  (let [s (clojure.string/join cs)]
    (str s (apply str (repeat (- 4 (count s)) "=")))))

(defn b64
  "Convert a string into Base64"
  [bs]
  (->> bs
   (hexify)
   (partition 3 3 [])
   (map b64-indexes)
   (map b64-lookup)
   (map b64-pad)
   (clojure.string/join)))
