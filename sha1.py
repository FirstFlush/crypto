
class SHA1:

    H = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    K = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]

    def __init__(self, message:bytes):
        self.message = message
        self.length = len(self.message) * 8 #msg length in bits
        self.preprocessing()
        self.main_loop()


    def _padding(self):
        """Pad the message until it is a length congruent to 448 mod 512"""
        self.message += int(128).to_bytes(1, 'big') # b'\x80'
        while (len(self.message) * 8) % 512 != 448:
            self.message += b'\x00'
        return


    def _append_length(self):
        """Appends the orginal length of the message as a 64bit integer.
        This is done to ensure that any change to the message's length will result
        in a different hash value.
        This prevents a type of attack called a "Length Extension Attack"
        """
        self.len64 = self.length.to_bytes((self.length.bit_length() + 7) // 8, byteorder='big').rjust(8, b'\x00')
        self.message += self.len64
        return


    def _create_message_blocks(self):
        """Chop the message into blocks of 512 bits. Check to make sure the length 
        of the final block is 512 bits. If its less than you have to perform SHA's
        funky little padding scheme: 
            -append 128 (b'\x80')
            -append zero bytes (b'\x00') until you are 1 byte short of 512 bits.
            -append the original message's length as a 64-bit integer
        """
        self.blocks = [self.message[i:i+64] for i in range(0, len(self.message), 64)]

        # ensure final block has a length of 512. Apply padding if it is less than 512. 
        if len(self.blocks[-1]) < 64:
            self.blocks[-1] += b'\x80'
            while (len(self.blocks[-1]) < 56):
                self.blocks[-1] += b'\x00'
                self.blocks[-1] += self.len64

        return


    def _left_rotate(self, n:int, d:int):
        return ((n << d) | (n >> (32 - d))) & 0xFFFFFFFF
    

    def preprocessing(self):
        self._padding()
        self._append_length()
        self._create_message_blocks()
        return


    def main_loop(self):

        for block in self.blocks:
            # Prepare the 16-word message schedule for this block
            W = [0] * 80
            for t in range(0, 16):
                W[t] = int().from_bytes(block[t * 4: (t + 1) * 4], 'big')

        for t in range(16, 80):
            W[t] = self._left_rotate(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1)

        a, b, c, d, e = self.H
        # Main loop iterations
        for t in range(80):
            if 0 <= t <= 19:
                f = (b & c) | ((~b) & d)
                k = self.K[0]
            elif 20 <= t <= 39:
                f = b ^ c ^ d
                k = self.K[1]
            elif 40 <= t <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = self.K[2]
            else:
                f = b ^ c ^ d
                k = self.K[3]

            temp = self._left_rotate(a, 5) + f + e + k + W[t]
            e, d, c, b, a = d, c, self._left_rotate(b, 30), a, temp & 0xFFFFFFFF

        # Update the intermediate hash values
        self.H[0] = (self.H[0] + a) & 0xFFFFFFFF
        self.H[1] = (self.H[1] + b) & 0xFFFFFFFF
        self.H[2] = (self.H[2] + c) & 0xFFFFFFFF
        self.H[3] = (self.H[3] + d) & 0xFFFFFFFF
        self.H[4] = (self.H[4] + e) & 0xFFFFFFFF

        return
    

    def sha1_hash(self, format:str='hex') -> str:
        """Format can be 'bytes' or 'hex'."""
        if format == 'bytes':    
            return b''.join(val.to_bytes(4, 'big') for val in self.H)
        else:
            return b''.join(val.to_bytes(4, 'big') for val in self.H).hex()
