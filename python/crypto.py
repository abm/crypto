import base64
import binascii
import itertools

def hex_to_b64(hex):
    return base64.b64encode(binascii.unhexlify(hex))

def b64_to_hex(b64):
    return binascii.hexlify(base64.b64decode(b64))

def xor_hex(a, b):
    return "".join(["{0:X}".format(x ^ y).zfill(2) for x, y in zip(map(ord, binascii.unhexlify(a)), map(ord, binascii.unhexlify(b)))])

def single_char_keys(length):
    for i in range(0, 256):
        yield "".join(itertools.repeat(binascii.hexlify(chr(i)), length))

def word_key(word):
    h = binascii.hexlify(word)
    yield "".join(bin

def repeated_key(hex_key, length):
    return hex_key*(length/len(hex_key)) + hex_key[0:length%len(hex_key)]
    
def decrypt(plaintext):
    return ["{0}\t{1}".format(key[0:2], binascii.unhexlify(xor_hex(plaintext, key))) for key in single_char_keys(len(plaintext)/2)]

messages = decrypt("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
# 58	Cooking MC's like a pound of bacon

with open("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736.txt","w") as output:
    output.write("\n".join(decrypt("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")))
    
with open("encrypted-messages.txt", "r") as messages:
    for message in messages:
        with open(message.rstrip()+".txt", "w") as output:
            output.write("\n".join(decrypt(message.rstrip())))

# 7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f 35/# Now that the party is jumping

def make_key(key):
    return binascii.hexlify(key)

def encrypt(plaintext, key):
    hex_key = binascii.hexlify(key)
    hex_plaintext = binascii.hexlify(plaintext)
    keylength = len(hex_key)
    full_key = hex_key*(len(hex_plaintext)/keylength) + hex_key[0:(len(hex_plaintext)%keylength)]
    return xor_hex(hex_plaintext, full_key)

def chunk(text, chunk_size):
    for i in xrange(0, len(text), chunk_size):
        yield text[i:i+chunk_size]

def pp_hex(hex):
    print " ".join(chunk(hex, 2))

def hamming(hex_a, hex_b):
    #hex_a = binascii.hexlify(a)
    #hex_b = binascii.hexlify(b)
    return sum(int(b) for b in bin(int(xor_hex(hex_a, hex_b), 16))[2:])

def interleave(text, chunk_size):
    gen = chunk(text, chunk_size)
    previous = gen.next()
    current = gen.next()
    while 1:
        yield (previous, current)
        previous = current
        current = gen.next()

def ed_of_keysize(text, keysize):
    return (hamming(a, b) for a, b in interleave(text, keysize*2))

with open('encrypted-xor.txt', 'r') as message:
    message_hex = b64_to_hex(message.read())

def avg_ed(hex, keysize):
    eds = list(ed_of_keysize(message_hex, keysize))
    return sum(eds) / float(len(eds*keysize))

best_keysize = min(((i, avg_ed(message_hex, i))) for i in range(2,41)), key=lambda p: p[1])[0]

def dump(path, lines):
    with open(path, 'w') as output:
        output.write("\n".join(lines))

with open('chunked.encrypted-xor.txt', 'w') as chunked:
    chunked.write("\n".join(chunk(message_hex, best_keysize*2)))

def column(lines, index):
    for line in lines:
        yield line[index*2:index*2+2]

def blockify(lines):
    columns = len(lines[0]) / 2
    for i in range(0, columns):
        yield "".join(column(lines, i))

blocks = list(blockify(list(chunk(message_hex, best_keysize*2))))
with open('blocked.encrypted-xor.txt', 'w') as blocked:
    blocked.write("\n".join(blocks))

def char_hist(line):
    return [(k, len(list(g))) for k, g in itertools.groupby(sorted(line.lower()))]

def top_chars(decrypted_messages):
    for message in decrypted_messages:
        key, msg = message.split('\t', 1) # in case there are any \t's in the msg
        yield key, "".join(map(lambda x: x[0], sorted(char_hist(msg), key=lambda entry: -entry[1])))

def top_chars_block(block):
    return list(top_chars(list(decrypt(block))))

# write out block histograms
for i in range(0, best_keysize):
    dump('block.'+str(i)+'.txt', [key+'\t'+chars for key, chars in top_chars_block(blocks[i])])

# find best candidates
def best(block):
    for key, chars in top_chars_block(block):
        if re.match('^[\w,\-\r\n \'\.!]+$', chars):
            yield key, chars

# 54 6
# 65 A
# 72 H
# 6d m
# 69 E
# 6e n
# 61 =
# 74 J
# 6f
# 72
# 20
# 58
# 3a

# 6AHmEn=J
# 5465726d696e61746f7220583a204272696e6720746865206e6f697365
key = "5465726d696e61746f7220583a204272696e6720746865206e6f697365"
print binascii.unhexlify(xor_hex(message_hex, repeated_key(key, len(message_hex))))

with open('ecb.txt', 'r') as input:
    ecb_lines = input.readlines()
    
filter(lambda l: len(l) > 0, (filter(lambda e: e[1] > 1, [(k, len(list(g))) for k, g in itertools.groupby(sorted(chunk(line.rstrip(), 16)))]) for line in ecb_lines))

# d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a
