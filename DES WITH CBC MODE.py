from typing import List
import binascii

IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]

FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]

E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

S_BOXES = [
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]

round_keys = [
    "101101111110000101100111101001011011010100000101",
    "001000010111110100010110110000011100010001011111",
    "011100010011001110101011010100001110110100110010",
    "010011011101001001001010111011000011010110010101",
    "101010101001100110001011010111110100110010111011",
    "110011010011001001010100111100001111110100010010",
    "111101001010010101011010100111110001011011101100",
    "011101110010110110001101110101110000110010011011",
    "101111000011110010110111001001000110101101001101",
    "001010111010011011001011101111001101011001101010",
    "011010110101100001111010010001110011100111001001",
    "110011101001101000010110011011001010011010110010",
    "110001000110001100101001110110100110101001110111",
    "001101110101100011001011101011010101110111010010",
    "001100111001000101111001010001001011110100101110",
    "110101001010010110100110011101001000101101111011"
]

iv = "1010101110110011001100110101010101011010010101010101011101101010"

def permute(block: str, table: List[int]) -> str:
    return ''.join([block[i - 1] for i in table])

def expand(block: str) -> str:
    return permute(block, E)

def xor(b1: str, b2: str) -> str:
    return ''.join(str(int(b1[i]) ^ int(b2[i])) for i in range(len(b1)))

def string_to_binary(input_string):
    return ''.join(format(ord(char), '08b') for char in input_string)


def binary_to_string(binary_string: str) -> str:
    import base64
    
    # Ensure the binary string's length is a multiple of 8
    if len(binary_string) % 8 != 0:
        binary_string = binary_string.ljust((len(binary_string) + 7) // 8 * 8, '0')
    
    # Convert each 8-bit chunk into a byte
    chunks = [binary_string[i:i+8] for i in range(0, len(binary_string), 8)]
    data_bytes = bytes(int(chunk, 2) for chunk in chunks)
    
    # Encode the bytes in Base64 for simple, readable output
    return base64.b64encode(data_bytes).decode("ascii")
    
    return result_string
def s_box(bits, index=0, result=""):
    
    if index == 8:
        return result
    
    target_bits = bits[:6]
    
    row = int(target_bits[0] + target_bits[5], 2)
    column = int(target_bits[1:5], 2)
    
    r = S_BOXES[index][row][column]
    
    return s_box(
        bits[6:], 
        index + 1, 
        result + f"{r:04b}" 
    )

def DES(bits):
    # doing the initial permutation
    bits = permute(bits, IP) 

    # splitting the bits into left and right
    left = bits[:32]
    right =bits[32:]

    # 16 rounds of DES
    for i in range(16):
        expanded = expand(right)
        #print(expanded)
        round_key = round_keys[i]
        xored = xor(expanded, round_keys[i])
        #print(xored)
        substituted = s_box(xored)
        #print(substituted)
        permuted = permute(substituted, P)
        #print(permuted)
        new_right = xor(left, permuted)
        #print(new_right)
        left = right
        right = new_right
    
    # swapping the left and right
    bits = right + left
    #print(bits)

    # final permutation
    ciphertext = permute(bits, FP)
    #print(ciphertext)
    return ciphertext

def CBC(plaintext, iv):
    blocks = [plaintext[i:i+64] for i in range(0, len(plaintext), 64)]
    ciphertext = ""
    prev_block = iv
    
    for block in blocks:
        # Pad block if necessary
        if len(block) < 64:
            # Add zeros to the left until block is 64 bits long
            block = block.zfill(64)
            
        # XOR with previous ciphertext block (or IV for first block)
        xored = xor(block, prev_block)
        
        # Encrypt using DES
        encrypted = DES(xored)
        
        # Add to result
        ciphertext += encrypted
        
        # Update previous block for next iteration
        prev_block = encrypted
        
    return ciphertext

def CBC_TEXT(text: str, iv: str) -> str:

    binary_plaintext = string_to_binary(text)
    
    # Encrypt using CBC mode
    binary_ciphertext = CBC(binary_plaintext, iv)
    
    string_ciphertext = binary_to_string(binary_ciphertext)
    
    return string_ciphertext

if __name__ == "__main__":
    # Define a test key and plaintext
    plaintext = "0000000100100011010001010110011110001001101010111100110111101111"
    
    # Encrypt using DES with CBC mode
    ciphertext = CBC(plaintext, iv)

    # Encrypt using DES without CBC mode
    ciphertext2 = DES(plaintext)

    # Encrypt using CBC mode with text input
    text = "Hello, World!"
    ciphertext3 = CBC_TEXT(text, iv)
    
    print(f"Plaintext:  {plaintext}")
    print(f"CBC: {ciphertext}")
    print(f"CBC_TEXT: {ciphertext3}")
    print(f"DES: {ciphertext2}")

