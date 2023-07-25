#     Preprocessing: Take the input message and perform some preprocessing steps. These include padding the message to a fixed length, appending the message length, and breaking the message into fixed-size blocks.

#     Initialize Variables: Define the initial hash values (H0 - H4) for SHA-1. These values are predetermined constants.

#     Main Loop: Process each block of the message in a loop. For each block, perform a series of logical and bitwise operations to update the hash values.

#     Hash Computation: Within each loop iteration, perform multiple rounds of operations. These rounds involve bitwise logical operations such as AND, OR, XOR, and logical functions such as NOT.

#     Finalize: After processing all the blocks, concatenate the final hash values together to get the resulting hash digest.

# To implement SHA-1 in Python, you can follow these steps:

#     Start by importing the required modules in your Python script. You may use the struct module for bit manipulation and binascii module for hex conversions.

#     Define the initial hash values (H0 - H4) as constants.

#     Implement the preprocessing steps, such as padding the input message to a fixed length and appending the message length. You may need to use bitwise operations and byte manipulation functions to perform these operations.

#     Write a function to process each block of the message. This function will include the main loop and the hash computation steps.

#     Implement the bitwise logical and arithmetic operations required by the SHA-1 algorithm. Make sure to use bitwise operators (&, |, ^, <<, >>) and logical functions (and, or, not) correctly.

#     Perform the necessary rounds of operations within the main loop to update the hash values.

#     Once all blocks have been processed, concatenate the final hash values to obtain the resulting hash digest.



import struct
import binascii


class SHA1:


    H = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    K = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]

    def __init__(self, message:bytes):
        self.message = message
        self.length = len(self.message) * 8 #msg length in bits


    def padding(self):
        """Pad the message until it is a length congruent to 448 mod 512"""
        self.message += int(128).to_bytes(1, 'big') # b'\x80'
        while (len(self.message) * 8) % 512 != 448:
            self.message += b'\x00'
        return


    def append_length(self):
        """Appends the orginal length of the message as a 64bit integer.
        This is done to ensure that any change to the message's length will result
        in a different hash value.
        This prevents a type of attack called a "Length Extension Attack"
        """
        self.len64 = self.length.to_bytes((self.length.bit_length() + 7) // 8, byteorder='big').rjust(8, b'\x00')
        self.message += self.len64
        self.message += self.message
        # self.message += self.message
        return


    def create_message_blocks(self):
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


    # def main_loop(self):

    #     for block in self.blocks:
    #         for i in range(0, 80):



    # def process_block(self, block:bytes):





    # def update(self, message:bytes) -> bytes:
    #     """
    #     This method should save the message, or if some text
    #     has already been added, just concatenate the incoming message
    #     to the saved message string.
    #     """
    #     msg_len = len(message) * 8
    #     message += int(128).to_bytes(1, 'big') # b'\x80'
        
    #     while (len(message) * 8) % 512 != 448:
    #         message += b'\x00'
    #     message += msg_len.to_bytes(8, 'big')
    #     return message


    # def digest(self) -> str:
    #     """
    #     This method should implement the SHA1 algorithm
    #     and output a 40 character string of hex letters.
    #     You may want to create other methods that will carry
    #     out the different parts of the algorithm and call
    #     them here.
    #     """
    #     pass




sha = SHA1(b'themessage')
sha.padding()
sha.append_length()
sha.create_message_blocks()
# print(sha.message)

# def sha1_padding(message):
#     ml = len(message) * 8  # Message length in bits
#     message += b'\x80'  # Append a single '1' bit (byte with value 128)

#     while (len(message) * 8) % 512 != 448:
#         message += b'\x00'  # Append '0' bits until the length is congruent to 448 mod 512

#     # Append the 64-bit big-endian representation of the original message length
#     message += ml.to_bytes(8, 'big')

#     return message

# # Example usage:
# original_message = b'Hello, world!'
# padded_message = sha1_padding(original_message)
# print(padded_message)