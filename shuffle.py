from FixedBinary import FixedBinary
import hashlib
import secrets
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def secure_dispose(var):
    if isinstance(var, FixedBinary):
        var = FixedBinary("0"*var.length, var.length)
    del var

def expand_key(key: FixedBinary, target_length: int) -> FixedBinary:
    try:
        if key.length == target_length:
            return key
        if key.length > target_length:
            return FixedBinary(key[:target_length], target_length)
        binary_key = ''.join(format(ord(c), '08b') for c in key)  # Convert key to binary
        expanded_key = ""
        hash_input = binary_key
        while len(expanded_key) < target_length:
            hash_output = hashlib.sha256(hash_input.encode()).hexdigest()  # Generate hash
            binary_hash = ''.join(format(int(h, 16), '04b') for h in hash_output)  # Hex to binary
            expanded_key += binary_hash
            hash_input = binary_hash  # Update hash input for next iteration
        
        # Truncate to the target length
        return FixedBinary(expanded_key[:target_length], target_length)
    except Exception as e:
        logging.error("Key expansion failed: %s", e)
        raise

def encrypt(message, key):
    try:
        logging.info("Beginning encryption...")
        #convert message into bits
        m = FixedBinary(message.encode("utf-8"))
        salt = secrets.token_bytes(8)
        salt = FixedBinary(salt, 8*8)
        m = salt + m
        
        #expand key or message to match sizes
        if m.length != key.length:
            key = expand_key(key, m.length)

        size = m.length

        ##Begin with an xor
        ##This helps with heavily padded messages (a message much smaller than the key)
        m = m ^ key

        ##
        #first shuffle: key -> message
        ##
        
        m = shuffle(m, key, size)


        ##
        #second round shuffle: reversed key -> message
        ##
        rkey = FixedBinary(key[::-1], size)
        m = shuffle(m, rkey, size)

        if m.length > 16:
            chunksize = m.length // 16
            extra_bit_count = m.length % 16
            if extra_bit_count > 0:
                hanging_bits = m[-extra_bit_count:]
                print("MADE HANGING BITS")
                m = FixedBinary(m[:-extra_bit_count], m.length - extra_bit_count)
            chunked = [m[i:i + chunksize] for i in range(0, m.length, chunksize)]
            chunkedKey = [key[i:i+4] for i in range(0,key.length, 4)]
            for i in range(len(chunkedKey)):
                pos = int(chunkedKey[i], 2)
                el = chunked.pop(pos)
                chunked.append(el)

            if extra_bit_count > 0:
                chunked.append(hanging_bits)
            m = FixedBinary("".join(chunked), size)
        
        m = shuffle(m, key, size)

        m = shuffle(m, rkey, size)

        m = salt + m
        
        secure_dispose(key)
        secure_dispose(salt)

        logging.info("Encryption completed successfully.")
        return m

    except Exception as e:
        logging.error("Encryption failed: %s", e)
        raise

def decrypt(ciphertext, key):
    try:
        salt_length = 8 * 8
        salt = FixedBinary(ciphertext[:salt_length], salt_length)
        c = FixedBinary(ciphertext[salt_length:], ciphertext.length-salt_length)

        if c.length != key.length:
            key = expand_key(key, c.length)

        rkey = FixedBinary(key[::-1], key.length)
        size = c.length
        halfsize = size//2

        c = unshuffle(c, rkey, size)

        c = unshuffle(c, key, size)

        if c.length > 16:
            chunksize = c.length // 16
            extra_bit_count = c.length % 16
            if extra_bit_count > 0:
                hanging_bits = c[-extra_bit_count:]
                c = FixedBinary(c[:-extra_bit_count], c.length - extra_bit_count)
            chunked = [c[i:i + chunksize] for i in range(0, c.length, chunksize)]
            chunkedKey = [key[i:i + 4] for i in range(0, key.length, 4)]

            # Reverse the chunk moving process
            for i in range(len(chunkedKey)-1, -1, -1):  # reverse loop over the chunkedKey
                pos = int(chunkedKey[i], 2)
                el = chunked.pop()  # Get the last element
                chunked.insert(pos, el)  # Insert it back to its original position

            # Combine the chunks back together
            if extra_bit_count > 0:
                chunked.append(hanging_bits)
            c = FixedBinary("".join(chunked), size)


        c = unshuffle(c, rkey, size)

        c = unshuffle(c, key, size)

        c = c ^ key

        c = c[salt.length:] #remove the salt

        secure_dispose(key)
        secure_dispose(rkey)

        logging.info("Decryption completed successfully.")

        return FixedBinary(c, size)
    except Exception as e:
        logging.error("Decryption failed: %s", e)
        raise

def shuffle(m, key, size):
    halfsize = size//2
    h1 = FixedBinary(m[:halfsize], halfsize)
    h2 = FixedBinary(m[halfsize:], halfsize)
    k1 = FixedBinary(key[:halfsize], halfsize)
    k2 = FixedBinary(key[halfsize:], halfsize)

    s1 = []
    for i in range(0, halfsize):
        top = h1[i]
        bottom = h2[i]
        test = k1[i]
        if test == "0":
            s1.append(top)
            s1.append(bottom)
        else:
            s1.append(bottom)
            s1.append(top)
    
    m = FixedBinary("".join(s1), size)
    h1 = FixedBinary(m[:halfsize], halfsize)
    h2 = FixedBinary(m[halfsize:], halfsize)
    s2 = []
    for i in range(0, halfsize):
        top = h1[i]
        bottom = h2[i]
        test = k2[i]
        if test == "0":
            s2.append(top)
            s2.append(bottom)
        else:
            s2.append(bottom)
            s2.append(top)

    m = FixedBinary("".join(s2), size)
    return m

def unshuffle(c, key, size):
    halfsize = size//2
    k1 = FixedBinary(key[:halfsize], halfsize)
    k2 = FixedBinary(key[halfsize:], halfsize)

    pairs = [c[i:i + 2] for i in range(0, c.length, 2)]

    h1 = []
    h2 = []

    for i in range(0, halfsize):
        test = k2[i]
        pair = pairs[i]
        if test == "0":
            h1.append(pair[0])
            h2.append(pair[1])
        else:
            h1.append(pair[1])
            h2.append(pair[0])
    
    joined = "".join(h1+h2)
    c = FixedBinary(joined, size)

    pairs = [c[i:i + 2] for i in range(0, c.length, 2)]
    h1 = []
    h2 = []

    for i in range(0, halfsize):
        test = k1[i]
        pair = pairs[i]
        if test == "0":
            h1.append(pair[0])
            h2.append(pair[1])
        else:
            h1.append(pair[1])
            h2.append(pair[0])
    
    joined = "".join(h1+h2)
    c = FixedBinary(joined, size)

    return c

def main():
    message = "shh, don't tell."
    m = FixedBinary(message.encode("utf-8"))
    key = FixedBinary('0xfa121315')

    secretMessage = encrypt(message, key)
    decryptedMessage = decrypt(secretMessage, key)

    print("---------------------")
    print("original message: ", message)
    print("secret message (hex): ", secretMessage.toHex())
    print("decrypted message: ", decryptedMessage.toUTF8())
    print("---------------------")

if __name__ == "__main__":
    main()
    