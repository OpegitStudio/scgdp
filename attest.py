# attest.py: some Python code to generate some 80 bytes based on some other 32 bytes to show you have outstanding byte generation skills
# or to put it simply, Hot Garbage Generator
# Usage: attest(request) -> bytes, where request is 32 bytes


import hashlib
import hmac
import struct
import secrets
import time

# REPLACE THIS VALUE WITH THE ACTUAL COMPANY NAME, FIRST LETTER IS CAPITALIZED 
COMPANY_NAME = b"AcmeCorporation"


def HASH_INTERNAL(REQUEST_PART1, SERVER_TIME, SERVER_MASK_FOR_HASH, SERVER_RANDOM):
    # I haven't followed chain of dependent values for this key, because it's content looks very much constant in nature
    SOME_KEY = COMPANY_NAME + b"APIkey0"

    # NOT COVERED BY TRACING: this was done but never used later. There is a chance it was just not covered, for example look at SERVER_MASK_FOR_HASH note below
    HINPUT_PARTIAL = hmac.new(SOME_KEY, struct.pack("<QQQ", REQUEST_PART1, SERVER_TIME, SERVER_MASK_FOR_HASH), digestmod="sha256").digest()

    if SERVER_MASK_FOR_HASH > 0xe:
        print("UNEXPECTED")
    
    SOME_WEIRD_HASH1 = None
    SOME_WEIRD_HASH2 = None
    SOME_WEIRD_HASH3 = None
    SOME_WEIRD_HASH4 = None

    if (SERVER_MASK_FOR_HASH & 0x1):
        SOME_WEIRD_HASH1 = hashlib.sha256(struct.pack("<QB", 1, SERVER_MASK_FOR_HASH)).digest()
    if (SERVER_MASK_FOR_HASH & 0x2):
        SOME_WEIRD_HASH2 = hashlib.sha256(struct.pack("<QB", 2, SERVER_MASK_FOR_HASH)).digest()
    if (SERVER_MASK_FOR_HASH & 0x4):
        SOME_WEIRD_HASH3 = hashlib.sha256(struct.pack("<QB", 4, SERVER_MASK_FOR_HASH)).digest()
    if (SERVER_MASK_FOR_HASH & 0x8):
        SOME_WEIRD_HASH4 = hashlib.sha256(struct.pack("<QB", 8, SERVER_MASK_FOR_HASH)).digest()

    HWEIRD1 = hmac.new(SOME_KEY, digestmod="sha256")
    HWEIRD2 = hmac.new(SOME_KEY, digestmod="sha256")

    # WARN: Code flow approximation below is probably wildly incorrect because it is based on incomplete tracing of data flow
    # SERVER_MASK_FOR_HASH was ONLY 0xe in all sample REQUESTs provided by the server, all the time
    # So other cases were NOT COVERED BY TRACING
    # Synthesizing own REQUESTs doesn't sound like a good idea because it would be very easy to violate constraints imposed on the values, if any
    # Speculation: for example I think HWEIRD_COMBINED could be not updated with HWEIRD1/2 if no updates were done to any of them
    # or HWEIRD_COMBINED itself could be not used at all if both HWEIRD weren't updated (less likely)
    # Even though all of this should be trivial to fix spending some time chasing values in disassembler, I don't want to. 
    # Let's left it as an exercise to the reader.

    if SOME_WEIRD_HASH1:
        HWEIRD1.update(SOME_WEIRD_HASH1)
    if SOME_WEIRD_HASH4:
        HWEIRD1.update(SOME_WEIRD_HASH4)

    if SOME_WEIRD_HASH2:
        HWEIRD2.update(SOME_WEIRD_HASH2)
    if SOME_WEIRD_HASH3:
        HWEIRD2.update(SOME_WEIRD_HASH3)


    HWEIRD_COMBINED = hmac.new(SOME_KEY, digestmod="sha256")
    HWEIRD_COMBINED.update(HWEIRD2.digest())
    HWEIRD_COMBINED.update(HWEIRD1.digest())

    RESULT = hmac.new(struct.pack("<QQQQ", REQUEST_PART1, SERVER_TIME, SERVER_MASK_FOR_HASH, SERVER_RANDOM), HWEIRD_COMBINED.digest(), digestmod="sha256").digest()

    # END WARN

    return RESULT


def MADD_64(a, b, c):
    return (a * b + c) & 0xFFFFFFFFFFFFFFFF


def ATTEST_INTERNAL(request: bytes, client_time: int, random: bytes):
    REQUEST = request
    CLIENT_TIME = client_time
    RANDOM, = struct.unpack("<Q", random)

    REQUEST_PART1, REQUEST_PART2, REQUEST_PART3, REQUEST_PART4 = struct.unpack("<QQQQ", REQUEST)

    SERVER_RANDOM = MADD_64(REQUEST_PART3, 0xfffffffffffffbfd, REQUEST_PART4)
    SERVER_MASK_FOR_HASH = MADD_64(REQUEST_PART2, 0xfffffffffffffbfd, REQUEST_PART3)
    SERVER_TIME = MADD_64(REQUEST_PART1, 0xfffffffffffffbfd, REQUEST_PART2)

    HASH_OUTPUT = HASH_INTERNAL(REQUEST_PART1, SERVER_TIME, SERVER_MASK_FOR_HASH, SERVER_RANDOM)

    REQUEST_DERIVED_HASH1, REQUEST_DERIVED_HASH2, REQUEST_DERIVED_HASH3, REQUEST_DERIVED_HASH4 = struct.unpack("<QQQQ", HASH_OUTPUT)

    RESULT_PART1 = RANDOM
    RESULT_PART2 = MADD_64(RESULT_PART1, 0x403, CLIENT_TIME)
    RESULT_PART3 = MADD_64(RESULT_PART2, 0x403, REQUEST_PART1)
    RESULT_PART4 = MADD_64(RESULT_PART3, 0x403, SERVER_TIME)
    RESULT_PART5 = MADD_64(RESULT_PART4, 0x403, SERVER_MASK_FOR_HASH)
    RESULT_PART6 = MADD_64(RESULT_PART5, 0x403, SERVER_RANDOM)
    RESULT_PART7 = MADD_64(RESULT_PART6, 0x403, REQUEST_DERIVED_HASH1)
    RESULT_PART8 = MADD_64(RESULT_PART7, 0x403, REQUEST_DERIVED_HASH2)
    RESULT_PART9 = MADD_64(RESULT_PART8, 0x403, REQUEST_DERIVED_HASH3)
    RESULT_PART10 = MADD_64(RESULT_PART9, 0x403, REQUEST_DERIVED_HASH4)

    RESULT = (
        RESULT_PART1, RESULT_PART2, RESULT_PART3, RESULT_PART4, RESULT_PART5,
        RESULT_PART6, RESULT_PART7, RESULT_PART8, RESULT_PART9, RESULT_PART10
    )

    result = struct.pack("<QQQQQQQQQQ", *RESULT)

    return result


def attest(request: bytes):
    assert len(request) == 32
    time_ = int(time.time())
    random = secrets.token_bytes(8)
    return ATTEST_INTERNAL(request, time_, random)


# If some parts of the code above can be considered copyrightable they are distributed under the following license:

# Copyright 2025 Opegit Studio

# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), 
# to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
# and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
