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

(defn b64
  "Convert a string into Base64"
  [bs]
  (->> bs
   (hexify)
   (partition 3 3 (repeat 0))))
