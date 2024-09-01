import os

# S-box used for SubWord operation
sbox = [
    # S-box array with 256 elements (0x00 to 0xFF)
    # (Precomputed AES S-box values)
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

InvSbox = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

# Round constants (Rcon)
rcon = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
]

class AES:

    def __init__(self, master_key):
        self.encrypted_file = ''
        self.decrypted_file = ''
        self.round_amount = 0
        self.round_keys = []
        self.master_key = master_key
        self.filename = "input.txt"

        print("How many rounds of AES cryptography do you want to perform?\n>", end = '')
        self.round_amount = int(input())

        print("TYpe the number that specifies what mode of operation you want to perform:\n")
        print("1 - Pure AES")
        print("2 - CTR mode")
        self.mode_of_operation = int(input())
        

        with open(self.filename, 'r') as file:
            self.input_message = file.read()

        # AES NORMAL MODE
        if self.mode_of_operation == 1:

            self.DoNormalAES()

        # AES CTR MODE
        elif self.mode_of_operation == 2:

            self.DoCTRAES()



    def DoNormalAES(self):

        self.encrypted_file = 'AES_Encrypted.txt'
        self.decrypted_file = 'AES_Decrypted.txt'

        # Turns input string into lists of 16 character stringsy
        self.input_message = [self.input_message[i:i+16] for i in range(0, len(self.input_message), 16)]

        # Encrypt plaintext and write to AES_Encrypted.txt
        write_encryption_file = open(self.encrypted_file, 'wb')
        for chunk in self.input_message:
            aux = self.Encrypt(chunk)
            for byte_sequence in aux:
                write_encryption_file.write(byte_sequence)
        write_encryption_file.close()


        # Read encrypted text from AES_Encrypted.txt
        read_encryption_file = open(self.encrypted_file, 'rb')
        encrypted_message = read_encryption_file.read()
        read_encryption_file.close()

        # Organizes encrypted data to list of lists with 16 bytes each
        chunks = [encrypted_message[i:i + 16] for i in range(0, len(encrypted_message), 16)]
        list_of_lists = [list(chunk) for chunk in chunks]

        # Decrypts and writes text to AES_Decrypted.txt
        write_decrypted_file = open(self.decrypted_file, 'w')
        for instance in list_of_lists:
            instance = self.TextToMatrix(instance)
            aux = self.Decrypt(instance)
            write_decrypted_file.write(aux)
        write_decrypted_file.close()

    def DoCTRAES(self):
        
        # encrypted_message = self.CTREncrypt(len(self.input_message))
        # # print(type(encrypted_message[0][0]))
        # # print(encrypted_message)

        # decrypted_message = self.CTRDecrypt(len(self.input_message), encrypted_message)
        # print(decrypted_message)

        self.encrypted_file = 'AES_CTR_Encrypted.txt'
        self.decrypted_file = 'AES_CTR_Decrypted.txt'

        # Turns input string into lists of 16 character stringsy
        self.input_message = [self.input_message[i:i+16] for i in range(0, len(self.input_message), 16)]


        # Encrypt plaintext and write to AES_Encrypted.txt
        write_encryption_file = open(self.encrypted_file, 'wb')
        encrypted_message = self.CTREncrypt(len(self.input_message))
        # print(encrypted_message)

        # Flatten the list of lists and convert each bytearray to bytes
        flattened_list = [byte for sublist in encrypted_message for byte in sublist]
        encrypted_message_bytes = b''.join(flattened_list)

        write_encryption_file.write(encrypted_message_bytes)
        write_encryption_file.close()

        # Read encrypted text from AES_Encrypted.txt
        read_encryption_file = open(self.encrypted_file, 'rb')
        encrypted_message = read_encryption_file.read()
        read_encryption_file.close()

        # Split the bytes into bytearrays and reconstruct the list
        offset = 0
        reconstructed_message = []
        for _ in range(len(encrypted_message)//4):
            # Extract a bytearray
            bytearray_chunk = encrypted_message[offset:offset + 4]
            reconstructed_message.append(bytearray(bytearray_chunk))
            offset += 4
        
        # Organize into lists of lists
        final_structure = [reconstructed_message[i:i + 4] for i in range(0, len(reconstructed_message), 4)]

         # Decrypts and writes text to AES_Decrypted.txt
        write_decrypted_file = open(self.decrypted_file, 'w')
        
        decrypted_message = self.CTRDecrypt(len(final_structure), final_structure)

        write_decrypted_file.write(decrypted_message)
        write_decrypted_file.close()



    def Encrypt(self, message_state):

        message_state = self.TextToMatrix(message_state)

        self.key_expansion(self.round_amount)

        message_state = self.AddRoundKey(message_state, 0)

        for round in range(1, self.round_amount):

            message_state = self.SubBytes(message_state)
            message_state = self.ShiftRows(message_state)
            message_state = self.MixColumns(message_state)
            message_state = self.AddRoundKey(message_state, round)

        message_state = self.SubBytes(message_state)
        message_state = self.ShiftRows(message_state)
        message_state = self.AddRoundKey(message_state, self.round_amount)

        return message_state



    def Decrypt(self, message_state):

        # message_state = self.TextToMatrix(message_state)

        message_state = self.AddRoundKey(message_state, self.round_amount)
        message_state = self.InverseShiftRows(message_state)
        message_state = self.InverseSubBytes(message_state)

        for round in range(self.round_amount-1, 0, -1):

            message_state = self.AddRoundKey(message_state, round)
            message_state = self.InverseMixColumns(message_state)
            message_state = self.InverseShiftRows(message_state)
            message_state = self.InverseSubBytes(message_state)

        message_state = self.AddRoundKey(message_state, 0)

        message_state = self.MatrixToText(message_state)

        return message_state



    def CTREncrypt(self, message_blocks_amount):

        self.iv = os.urandom(16)  # Generate a random 16-byte IV
        
        self.key_expansion(self.round_amount)

        # calculate counters
        counters = self.GenerateCountersCTR(self.iv, message_blocks_amount)

        # encrypt counters
        encrypted_counters = []
        for counter in counters:
            encrypted_counters.append(self.Encrypt(counter))

        # xor plaintext with encrypted counters

        list_of_messages = []
        list_of_messages.clear()
        for plain_text_instance in self.input_message:
            list_of_messages.append(self.TextToMatrix(plain_text_instance))
        # print(list_of_messages)

        encrypted_message = []
        for count in range(len(self.input_message)):
            # Ensure list_of_messages[count] and encrypted_counters[count] are bytearrays
            list_of_messages[count] = [bytearray(row) for row in list_of_messages[count]]
            encrypted_counters[count] = [bytearray(row) for row in encrypted_counters[count]]

            # Perform the XOR operation
            for i in range(4):
                for j in range(4):
                    list_of_messages[count][i][j] ^= encrypted_counters[count][i][j]

            encrypted_message.append(list_of_messages[count])


        return encrypted_message



    def CTRDecrypt(self, message_blocks_amount, encrypted_text):

        # calculate counters
        counters = self.GenerateCountersCTR(self.iv, message_blocks_amount)

        # encrypt counters
        encrypted_counters = []
        for counter in counters:
            encrypted_counters.append(self.Encrypt(counter))
        
        # xor cyphertext with encrypted counters

        decrypted_message = []
        for count in range(len(encrypted_text)):

            # Perform the XOR operation
            for i in range(4):
                for j in range(4):
                    encrypted_text[count][i][j] ^= encrypted_counters[count][i][j]

            decrypted_message.append(encrypted_text[count])

        # convert nested byte array "decrypted_message" into a string
        flattened_bytearray = bytearray()
        for sublist in decrypted_message:
            for bytearr in sublist:
                flattened_bytearray.extend(bytearr)

        result_string = flattened_bytearray.decode('utf-8', errors='ignore').rstrip('\x00')

        return result_string



    def GenerateCountersCTR(self, iv, counter_amount):
        # Lista com os contadores 
        counters = []
        # Counter
        iv = int.from_bytes(bytes(iv), byteorder='big')
        
        for j in range(counter_amount):
            counters.append(iv.to_bytes(16, byteorder='big'))
            iv += 1
        
        return counters



    def key_expansion(self, round_amount):
        # Initialize the round keys with the master key
        self.round_keys = self.TextToMatrix(self.master_key)

        # Number of words in the expanded key
        total_words = 4 * (round_amount + 1)

        for i in range(4, total_words):
            temp = self.round_keys[i - 1][:]  # Copy the last word
            if i % 4 == 0:
                # Perform the key schedule core
                temp = [sbox[temp[1]] ^ rcon[i // 4]] + [sbox[temp[(j + 1) % 4]] for j in range(4)]
            
            # XOR with the word 4 positions back
            self.round_keys.append([self.round_keys[i - 4][j] ^ temp[j] for j in range(4)])



    def TextToMatrix(self, text):

        if isinstance(text, str):
            byte_array = text.encode('utf-8')
        
        else:
            byte_array = text

        # Ensure the byte array is exactly 16 bytes long
        if len(byte_array) < 16:
            byte_array += b'\x00' * (16 - len(byte_array))  # Pad with null bytes if needed
        elif len(byte_array) > 16:
            byte_array = byte_array[:16]  # Trim if longer than 16 bytes

        return [byte_array[i*4:(i+1)*4] for i in range(4)]



    def MatrixToText(self, matrix):
        # Flatten the 4x4 matrix into a single byte array
        byte_array = bytes([matrix[i][j] for i in range(4) for j in range(4)])
        
        # Convert the byte array to a string
        text = byte_array.decode('utf-8', errors='ignore')  # Ignore errors if there are invalid UTF-8 sequences
        
        # Optionally remove padding if you know the padding scheme
        return text.rstrip('\x00')  # Remove null byte padding if it was used



    def AddRoundKey(self, text, nth_round):

        text = [bytearray(row) for row in text]
        self.round_keys = [bytearray(row) for row in self.round_keys]

        for i in range(4):
            for j in range(4):
                text[i][j] ^= self.round_keys[i + nth_round * 4][j]

        # Convert the text back to bytes
        text = [bytes(row) for row in text]

        return text



    def SubBytes(self, matrix):

        matrix = [bytearray(row) for row in matrix]

        # Convert the text back to bytes

        for i in range(4):
            for j in range(4):
                matrix[i][j] = sbox[matrix[i][j]]
    
        matrix = [bytes(row) for row in matrix]

        return matrix



    def InverseSubBytes(self, matrix):

        matrix = [bytearray(row) for row in matrix]

        for i in range(4):
            for j in range(4):
                matrix[i][j] = InvSbox[matrix[i][j]]
        
        matrix = [bytes(row) for row in matrix]

        return matrix



    def ShiftRows(self, matrix):

        matrix = [bytearray(row) for row in matrix]

        matrix[0][1], matrix[1][1], matrix[2][1], matrix[3][1] = matrix[1][1], matrix[2][1], matrix[3][1], matrix[0][1]
        matrix[0][2], matrix[1][2], matrix[2][2], matrix[3][2] = matrix[2][2], matrix[3][2], matrix[0][2], matrix[1][2]
        matrix[0][3], matrix[1][3], matrix[2][3], matrix[3][3] = matrix[3][3], matrix[0][3], matrix[1][3], matrix[2][3]

        matrix = [bytes(row) for row in matrix]

        return matrix



    def InverseShiftRows(self, matrix):

        matrix = [bytearray(row) for row in matrix]

        matrix[0][1], matrix[1][1], matrix[2][1], matrix[3][1] = matrix[3][1], matrix[0][1], matrix[1][1], matrix[2][1]
        matrix[0][2], matrix[1][2], matrix[2][2], matrix[3][2] = matrix[2][2], matrix[3][2], matrix[0][2], matrix[1][2]
        matrix[0][3], matrix[1][3], matrix[2][3], matrix[3][3] = matrix[1][3], matrix[2][3], matrix[3][3], matrix[0][3]

        matrix = [bytes(row) for row in matrix]

        return matrix



    def MixColumns(self, matrix):
        
        gfp2 = [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64, 66, 68, 70, 72, 74, 76, 78, 80, 82, 84, 86, 88, 90, 92, 94, 96, 98, 100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126, 128, 130, 132, 134, 136, 138, 140, 142, 144, 146, 148, 150, 152, 154, 156, 158, 160, 162, 164, 166, 168, 170, 172, 174, 176, 178, 180, 182, 184, 186, 188, 190, 192, 194, 196, 198, 200, 202, 204, 206, 208, 210, 212, 214, 216, 218, 220, 222, 224, 226, 228, 230, 232, 234, 236, 238, 240, 242, 244, 246, 248, 250, 252, 254, 27, 25, 31, 29, 19, 17, 23, 21, 11, 9, 15, 13, 3, 1, 7, 5, 59, 57, 63, 61, 51, 49, 55, 53, 43, 41, 47, 45, 35, 33, 39, 37, 91, 89, 95, 93, 83, 81, 87, 85, 75, 73, 79, 77, 67, 65, 71, 69, 123, 121, 127, 125, 115, 113, 119, 117, 107, 105, 111, 109, 99, 97, 103, 101, 155, 153, 159, 157, 147, 145, 151, 149, 139, 137, 143, 141, 131, 129, 135, 133, 187, 185, 191, 189, 179, 177, 183, 181, 171, 169, 175, 173, 163, 161, 167, 165, 219, 217, 223, 221, 211, 209, 215, 213, 203, 201, 207, 205, 195, 193, 199, 197, 251, 249, 255, 253, 243, 241, 247, 245, 235, 233, 239, 237, 227, 225, 231, 229]

        gfp3 = [0, 3, 6, 5, 12, 15, 10, 9, 24, 27, 30, 29, 20, 23, 18, 17, 48, 51, 54, 53, 60, 63, 58, 57, 40, 43, 46, 45, 36, 39, 34, 33, 96, 99, 102, 101, 108, 111, 106, 105, 120, 123, 126, 125, 116, 119, 114, 113, 80, 83, 86, 85, 92, 95, 90, 89, 72, 75, 78, 77, 68, 71, 66, 65, 192, 195, 198, 197, 204, 207, 202, 201, 216, 219, 222, 221, 212, 215, 210, 209, 240, 243, 246, 245, 252, 255, 250, 249, 232, 235, 238, 237, 228, 231, 226, 225, 160, 163, 166, 165, 172, 175, 170, 169, 184, 187, 190, 189, 180, 183, 178, 177, 144, 147, 150, 149, 156, 159, 154, 153, 136, 139, 142, 141, 132, 135, 130, 129, 155, 152, 157, 158, 151, 148, 145, 146, 131, 128, 133, 134, 143, 140, 137, 138, 171, 168, 173, 174, 167, 164, 161, 162, 179, 176, 181, 182, 191, 188, 185, 186, 251, 248, 253, 254, 247, 244, 241, 242, 227, 224, 229, 230, 239, 236, 233, 234, 203, 200, 205, 206, 199, 196, 193, 194, 211, 208, 213, 214, 223, 220, 217, 218, 91, 88, 93, 94, 87, 84, 81, 82, 67, 64, 69, 70, 79, 76, 73, 74, 107, 104, 109, 110, 103, 100, 97, 98, 115, 112, 117, 118, 127, 124, 121, 122, 59, 56, 61, 62, 55, 52, 49, 50, 35, 32, 37, 38, 47, 44, 41, 42, 11, 8, 13, 14, 7, 4, 1, 2, 19, 16, 21, 22, 31, 28, 25, 26]

        matrix = [bytearray(row) for row in matrix]


        Nb = len(matrix)
        n = [word[:] for word in matrix]

        for i in range(Nb):
            n[i][0] = (gfp2[matrix[i][0]] ^ gfp3[matrix[i][1]]
                    ^ matrix[i][2] ^ matrix[i][3])
            n[i][1] = (matrix[i][0] ^ gfp2[matrix[i][1]]
                    ^ gfp3[matrix[i][2]] ^ matrix[i][3])
            n[i][2] = (matrix[i][0] ^ matrix[i][1]
                    ^ gfp2[matrix[i][2]] ^ gfp3[matrix[i][3]])
            n[i][3] = (gfp3[matrix[i][0]] ^ matrix[i][1]
                    ^ matrix[i][2] ^ gfp2[matrix[i][3]])

        n = [bytes(row) for row in n]

        return n



    def InverseMixColumns(self, matrix):

        gfp9 = [0, 9, 18, 27, 36, 45, 54, 63, 72, 65, 90, 83, 108, 101, 126, 119, 144, 153, 130, 139, 180, 189, 166, 175, 216, 209, 202, 195, 252, 245, 238, 231, 59, 50, 41, 32, 31, 22, 13, 4, 115, 122, 97, 104, 87, 94, 69, 76, 171, 162, 185, 176, 143, 134, 157, 148, 227, 234, 241, 248, 199, 206, 213, 220, 118, 127, 100, 109, 82, 91, 64, 73, 62, 55, 44, 37, 26, 19, 8, 1, 230, 239, 244, 253, 194, 203, 208, 217, 174, 167, 188, 181, 138, 131, 152, 145, 77, 68, 95, 86, 105, 96, 123, 114, 5, 12, 23, 30, 33, 40, 51, 58, 221, 212, 207, 198, 249, 240, 235, 226, 149, 156, 135, 142, 177, 184, 163, 170, 236, 229, 254, 247, 200, 193, 218, 211, 164, 173, 182, 191, 128, 137, 146, 155, 124, 117, 110, 103, 88, 81, 74, 67, 52, 61, 38, 47, 16, 25, 2, 11, 215, 222, 197, 204, 243, 250, 225, 232, 159, 150, 141, 132, 187, 178, 169, 160, 71, 78, 85, 92, 99, 106, 113, 120, 15, 6, 29, 20, 43, 34, 57, 48, 154, 147, 136, 129, 190, 183, 172, 165, 210, 219, 192, 201, 246, 255, 228, 237, 10, 3, 24, 17, 46, 39, 60, 53, 66, 75, 80, 89, 102, 111, 116, 125, 161, 168, 179, 186, 133, 140, 151, 158, 233, 224, 251, 242, 205, 196, 223, 214, 49, 56, 35, 42, 21, 28, 7, 14, 121, 112, 107, 98, 93, 84, 79, 70]

        gfp11 = [0, 11, 22, 29, 44, 39, 58, 49, 88, 83, 78, 69, 116, 127, 98, 105, 176, 187, 166, 173, 156, 151, 138, 129, 232, 227, 254, 245, 196, 207, 210, 217, 123, 112, 109, 102, 87, 92, 65, 74, 35, 40, 53, 62, 15, 4, 25, 18, 203, 192, 221, 214, 231, 236, 241, 250, 147, 152, 133, 142, 191, 180, 169, 162, 246, 253, 224, 235, 218, 209, 204, 199, 174, 165, 184, 179, 130, 137, 148, 159, 70, 77, 80, 91, 106, 97, 124, 119, 30, 21, 8, 3, 50, 57, 36, 47, 141, 134, 155, 144, 161, 170, 183, 188, 213, 222, 195, 200, 249, 242, 239, 228, 61, 54, 43, 32, 17, 26, 7, 12, 101, 110, 115, 120, 73, 66, 95, 84, 247, 252, 225, 234, 219, 208, 205, 198, 175, 164, 185, 178, 131, 136, 149, 158, 71, 76, 81, 90, 107, 96, 125, 118, 31, 20, 9, 2, 51, 56, 37, 46, 140, 135, 154, 145, 160, 171, 182, 189, 212, 223, 194, 201, 248, 243, 238, 229, 60, 55, 42, 33, 16, 27, 6, 13, 100, 111, 114, 121, 72, 67, 94, 85, 1, 10, 23, 28, 45, 38, 59, 48, 89, 82, 79, 68, 117, 126, 99, 104, 177, 186, 167, 172, 157, 150, 139, 128, 233, 226, 255, 244, 197, 206, 211, 216, 122, 113, 108, 103, 86, 93, 64, 75, 34, 41, 52, 63, 14, 5, 24, 19, 202, 193, 220, 215, 230, 237, 240, 251, 146, 153, 132, 143, 190, 181, 168, 163]

        gfp13 = [0, 13, 26, 23, 52, 57, 46, 35, 104, 101, 114, 127, 92, 81, 70, 75, 208, 221, 202, 199, 228, 233, 254, 243, 184, 181, 162, 175, 140, 129, 150, 155, 187, 182, 161, 172, 143, 130, 149, 152, 211, 222, 201, 196, 231, 234, 253, 240, 107, 102, 113, 124, 95, 82, 69, 72, 3, 14, 25, 20, 55, 58, 45, 32, 109, 96, 119, 122, 89, 84, 67, 78, 5, 8, 31, 18, 49, 60, 43, 38, 189, 176, 167, 170, 137, 132, 147, 158, 213, 216, 207, 194, 225, 236, 251, 246, 214, 219, 204, 193, 226, 239, 248, 245, 190, 179, 164, 169, 138, 135, 144, 157, 6, 11, 28, 17, 50, 63, 40, 37, 110, 99, 116, 121, 90, 87, 64, 77, 218, 215, 192, 205, 238, 227, 244, 249, 178, 191, 168, 165, 134, 139, 156, 145, 10, 7, 16, 29, 62, 51, 36, 41, 98, 111, 120, 117, 86, 91, 76, 65, 97, 108, 123, 118, 85, 88, 79, 66, 9, 4, 19, 30, 61, 48, 39, 42, 177, 188, 171, 166, 133, 136, 159, 146, 217, 212, 195, 206, 237, 224, 247, 250, 183, 186, 173, 160, 131, 142, 153, 148, 223, 210, 197, 200, 235, 230, 241, 252, 103, 106, 125, 112, 83, 94, 73, 68, 15, 2, 21, 24, 59, 54, 33, 44, 12, 1, 22, 27, 56, 53, 34, 47, 100, 105, 126, 115, 80, 93, 74, 71, 220, 209, 198, 203, 232, 229, 242, 255, 180, 185, 174, 163, 128, 141, 154, 151]

        gfp14 = [0, 14, 28, 18, 56, 54, 36, 42, 112, 126, 108, 98, 72, 70, 84, 90, 224, 238, 252, 242, 216, 214, 196, 202, 144, 158, 140, 130, 168, 166, 180, 186, 219, 213, 199, 201, 227, 237, 255, 241, 171, 165, 183, 185, 147, 157, 143, 129, 59, 53, 39, 41, 3, 13, 31, 17, 75, 69, 87, 89, 115, 125, 111, 97, 173, 163, 177, 191, 149, 155, 137, 135, 221, 211, 193, 207, 229, 235, 249, 247, 77, 67, 81, 95, 117, 123, 105, 103, 61, 51, 33, 47, 5, 11, 25, 23, 118, 120, 106, 100, 78, 64, 82, 92, 6, 8, 26, 20, 62, 48, 34, 44, 150, 152, 138, 132, 174, 160, 178, 188, 230, 232, 250, 244, 222, 208, 194, 204, 65, 79, 93, 83, 121, 119, 101, 107, 49, 63, 45, 35, 9, 7, 21, 27, 161, 175, 189, 179, 153, 151, 133, 139, 209, 223, 205, 195, 233, 231, 245, 251, 154, 148, 134, 136, 162, 172, 190, 176, 234, 228, 246, 248, 210, 220, 206, 192, 122, 116, 102, 104, 66, 76, 94, 80, 10, 4, 22, 24, 50, 60, 46, 32, 236, 226, 240, 254, 212, 218, 200, 198, 156, 146, 128, 142, 164, 170, 184, 182, 12, 2, 16, 30, 52, 58, 40, 38, 124, 114, 96, 110, 68, 74, 88, 86, 55, 57, 43, 37, 15, 1, 19, 29, 71, 73, 91, 85, 127, 113, 99, 109, 215, 217, 203, 197, 239, 225, 243, 253, 167, 169, 187, 181, 159, 145, 131, 141]

        matrix = [bytearray(row) for row in matrix]

        Nb = len(matrix)
        n = [word[:] for word in matrix]

        for i in range(Nb):
            n[i][0] = (gfp14[matrix[i][0]] ^ gfp11[matrix[i][1]]
                    ^ gfp13[matrix[i][2]] ^ gfp9[matrix[i][3]])
            n[i][1] = (gfp9[matrix[i][0]] ^ gfp14[matrix[i][1]]
                    ^ gfp11[matrix[i][2]] ^ gfp13[matrix[i][3]])
            n[i][2] = (gfp13[matrix[i][0]] ^ gfp9[matrix[i][1]]
                    ^ gfp14[matrix[i][2]] ^ gfp11[matrix[i][3]])
            n[i][3] = (gfp11[matrix[i][0]] ^ gfp13[matrix[i][1]]
                    ^ gfp9[matrix[i][2]] ^ gfp14[matrix[i][3]])

        n = [bytes(row) for row in n]

        return n

# y = AES(0x2b7e151628aed2a6abf7158809cf4f3c)
y = AES("abcdefghijklmnop")
