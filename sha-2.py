#SHA256.
import time
import os
import psutil

def right_rotate(value, bits):
    #ROT32
    x = ((value >> bits) | (value << (32 - bits))) & 0xFFFFFFFF

    return x

def sha256_transform(h,data):
    #SHA-256 transformation.
    k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]

    def ch(x, y, z):
        res = (x & y) ^ (~x & z)
        return res

    def maj(x, y, z):
        res = (x & y) ^ (x & z) ^ (y & z)
        return res

    def sigma0(x):
        res = right_rotate(x, 2) ^ right_rotate(x, 13) ^ right_rotate(x, 22)
        return res

    def sigma1(x):
        res = right_rotate(x, 6) ^ right_rotate(x, 11) ^ right_rotate(x, 25)
        return res

    def delta0(x):
        res = right_rotate(x, 7) ^ right_rotate(x, 18) ^ (x >> 3)
        return res

    def delta1(x):
        res =  right_rotate(x, 17) ^ right_rotate(x, 19) ^ (x >> 10)
        return res


    w = [0] * 64

    for i in range(16):
        w[i] = int.from_bytes(data[i * 4:(i + 1) * 4], "big")
    
    for i in range(16, 64):
        w[i] = (delta1(w[i - 2]) + w[i - 7] + delta0(w[i - 15]) + w[i - 16]) & 0xFFFFFFFF

    a, b, c, d, e, f, g, h0 = h

    for i in range(64):
        t1 = (h0 + sigma1(e) + ch(e, f, g) + k[i] + w[i]) & 0xFFFFFFFF
        t2 = (sigma0(a) + maj(a, b, c)) & 0xFFFFFFFF
        h0 = g
        g = f
        f = e
        e = (d + t1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (t1 + t2) & 0xFFFFFFFF

    h[0] = (h[0] + a) & 0xFFFFFFFF
    h[1] = (h[1] + b) & 0xFFFFFFFF
    h[2] = (h[2] + c) & 0xFFFFFFFF
    h[3] = (h[3] + d) & 0xFFFFFFFF
    h[4] = (h[4] + e) & 0xFFFFFFFF
    h[5] = (h[5] + f) & 0xFFFFFFFF
    h[6] = (h[6] + g) & 0xFFFFFFFF
    h[7] = (h[7] + h0) & 0xFFFFFFFF

    return h
    
def sha256(message):

    #SHA 256 Calculation.
    
    message = message.encode("utf-8")
    original_length = len(message) * 8
    message += b"\x80"
    while (len(message) % 64) != 56:
        message += b"\x00"
    message += original_length.to_bytes(8, "big")

    h = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]

    for i in range(0, len(message), 64):
        h = sha256_transform(h, message[i:i + 64])

    return "".join(f"{x:08x}" for x in h)


message = input("Enter a string to hash: ")
print("Computing hash...")

start_time = time.time()
hash_value = sha256(message)

print("SHA-256 hash : ", hash_value)

end_time = time.time()

time_taken = (end_time - start_time)*1000
print(f"Time taken to compute hash: {time_taken:.9f} ms")


