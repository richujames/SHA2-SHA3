import numpy as np
import time
import os
import psutil

def get_memory_usage():
    process = psutil.Process(os.getpid())
    memory_info = process.memory_info()
    return memory_info.rss

# Pre-processing of the message
def pad(message, blocksize):
    if isinstance(message, str):
        message = message.encode('utf-8')
    padded_message = message + b'\x06'  # 0b0110 for SHA3
    pad_length = blocksize - (len(padded_message) % blocksize)
    padded_message += b'\x00' * (pad_length - 1) + b'\x80'
    return padded_message


def absorb(padded_message, state, rate_bytes):
    for i in range(0, len(padded_message), rate_bytes):
        block = padded_message[i:i + rate_bytes]
        for j in range(0, len(block), 8):
            if j + 8 <= len(block):
                word = int.from_bytes(block[j:j+8], 'little')
                x, y = (j // 8) % 5, (j // 8) // 5
                state[x, y] ^= np.uint64(word)
        for round in range(24):
            state = iota(chi(pi(rho(theta(state)))), round)
    return state

def squeeze(state, output_length):
    #convert state to byte in little-endian order
    result = bytearray()
    for i in range(output_length // 8):
        lane_idx = i // 8
        x, y = lane_idx % 5, lane_idx // 5
        if x < 5 and y < 5:
            lane = int(state[x, y]).to_bytes(8, 'little')
            result.extend(lane[i % 8:i % 8 + 1])
    return bytes(result)

# f function

# theta function
def theta(state):
    C = np.zeros(5, dtype=np.uint64)
    D = np.zeros(5, dtype=np.uint64)
    
    for x in range(5):
        C[x] = state[x, 0] ^ state[x, 1] ^ state[x, 2] ^ state[x, 3] ^ state[x, 4]
    
    for x in range(5):
        D[x] = C[(x-1) % 5] ^ np.uint64(((int(C[(x+1) % 5]) << 1) | (int(C[(x+1) % 5]) >> 63)) & 0xFFFFFFFFFFFFFFFF)
    
    for x in range(5):
        for y in range(5):
            state[x, y] ^= D[x]
    
    return state


# rho step
def rho(state):
    rotation_offsets = [
        [0, 36, 3, 41, 18],
        [1, 44, 10, 45, 2],
        [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39, 8, 14]
    ]
    
    result = np.zeros_like(state)
    for x in range(5):
        for y in range(5):
            value = int(state[x, y])
            shift = rotation_offsets[x][y]
            rotated = ((value << shift) | (value >> (64 - shift))) & 0xFFFFFFFFFFFFFFFF
            result[x, y] = np.uint64(rotated)
    
    return result

# pi step
def pi(state):
    result = np.zeros_like(state)
    for x in range(5):
        for y in range(5):
            result[y, (2*x + 3*y) % 5] = state[x, y]
    return result

# chi step
def chi(state):
    result = np.zeros_like(state)
    for x in range(5):
        for y in range(5):
            result[x, y] = state[x, y] ^ (~state[(x+1) % 5, y] & state[(x+2) % 5, y])
    return result

# iota step
def iota(state, round_index):
    RC = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
        0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008
    ]
    state[0, 0] ^= np.uint64(RC[round_index])
    return state


def sha3_256(message):
    blocksize = 1088 // 8
    state = np.zeros((5, 5), dtype=np.uint64)
    padded_message = pad(message, blocksize)
    final_state = absorb(padded_message, state, blocksize)
    return squeeze(final_state, 256).hex()


startTime = time.time()
message = input("Enter the message you want to hash: ")
print(f'SHA3-256 Hash: {sha3_256(message)}')
endTime = time.time()
timeTaken = (endTime - startTime)
print(f'Time taken to compute hash: {timeTaken:.9f} ms')

memoryUsed = get_memory_usage()
print(f'Memory used by the program: {memoryUsed / (1024 ** 2):.2f} MB')