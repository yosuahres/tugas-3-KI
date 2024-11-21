import socket
import json


# DES Algorithm

ip_table = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]
pc1_table = [
    57, 49, 41, 33, 25, 17, 9, 1,
    58, 50, 42, 34, 26, 18, 10, 2,
    59, 51, 43, 35, 27, 19, 11, 3,
    60, 52, 44, 36, 63, 55, 47, 39,
    31, 23, 15, 7, 62, 54, 46, 38,
    30, 22, 14, 6, 61, 53, 45, 37,
    29, 21, 13, 5, 28, 20, 12, 4
]
shift_schedule = [1, 1, 2, 2,
                  2, 2, 2, 2,
                  1, 2, 2, 2,
                  2, 2, 2, 1]
pc2_table = [
    14, 17, 11, 24, 1, 5, 3, 28,
    15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32
]
e_box_table = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]
subtitution_box = [
    # S-box 1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # S-box 2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    # S-box 3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    # S-box 4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    # S-box 5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    # S-box 6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    # S-box 7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    # S-box 8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]
p_box_table = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
]
ip_inverse_table = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

des_key = ""

def str_to_bin(user_input):
    
    binary_str = ''
    
    for char in user_input:

        binary_char = format(ord(char), '08b')
        binary_str += binary_char
        binary_str = binary_str[:64]
    
    binary_str = binary_str[:64].ljust(64, '0')
    
    return binary_str

def binary_to_ascii(binary_str):
    ascii_str = ''.join([chr(int(binary_str[i:i+8], 2)) for i in range(0, len(binary_str), 8)])
    return ascii_str

def key_to_bin_enc():

    original_key = des_key
    binary_key_result = ''
    
    for char in original_key:

        binary_key = format(ord(char), '08b') 
        binary_key_result += binary_key

    return binary_key_result

def key_to_bin_dec():

    original_key = des_key
    binary_key_result = ''
    
    for char in original_key:

        binary_key = format(ord(char), '08b') 
        binary_key_result += binary_key

    return binary_key_result

def generate_round_keys(binary_key_result):

    pc1_key_str = ''.join(binary_key_result[bit - 1] for bit in pc1_table)

    c0 = pc1_key_str[:28]
    d0 = pc1_key_str[28:]
    round_keys = []

    for round_num in range(16):

        c0 = c0[shift_schedule[round_num]:] + c0[:shift_schedule[round_num]]
        d0 = d0[shift_schedule[round_num]:] + d0[:shift_schedule[round_num]]

        cd_merge = c0 + d0

        round_key = ''.join(cd_merge[bit - 1] for bit in pc2_table)

        round_keys.append(round_key)
    return round_keys

def initial_permutation(binary_str):
    
    ip_result = [None] * 64
    
    for i in range(64):
        ip_result[i] = binary_str[ip_table[i] - 1]

    ip_result_str = ''.join(ip_result)
    
    return ip_result_str

def encryption(user_input):
    binary_input = str_to_bin(user_input)

    # Membuat 16 putaran keys
    round_keys = generate_round_keys(key_to_bin_enc())

    # Initial Permutation
    ip_result_str = initial_permutation(binary_input)

    lpt = ip_result_str[:32] # Left Part
    rpt = ip_result_str[32:] # Right Part

    for round_num in range(16):
        # Expansion 32 bit -> 48 bit
        expanded_result = [rpt[i - 1] for i in e_box_table]
        expanded_result_str = ''.join(expanded_result)

        round_key_str = round_keys[round_num]

        xor_result_str = ''
        for i in range(48):
            xor_result_str += str(int(expanded_result_str[i]) ^ int(round_key_str[i]))

        # Membagi menjadi 8 grup berisi 6 bit
        six_bit_groups = [xor_result_str[i:i+6] for i in range(0, 48, 6)]

        subtitution_result = ''

        for i in range(8):
            # row_bits berisi bit awal dan terakhir
            row_bits = int(six_bit_groups[i][0] + six_bit_groups[i][-1], 2)

            # col_bits berisi 4-bit yang ada di tengah
            col_bits = int(six_bit_groups[i][1:-1], 2)

            s_box_value = subtitution_box[i][row_bits][col_bits]
            
            subtitution_result += format(s_box_value, '04b')

        p_box_result = [subtitution_result[i - 1] for i in p_box_table]

        lpt_list = list(lpt)

        # XOR Left Part dan Hasil Permutasi
        new_rpt = [str(int(lpt_list[i]) ^ int(p_box_result[i])) for i in range(32)]

        new_rpt_str = ''.join(new_rpt)

        lpt = rpt
        rpt = new_rpt_str

    final_result = rpt + lpt

    # final permutation (IP-1)
    final_cipher = [final_result[ip_inverse_table[i] - 1] for i in range(64)]

    final_cipher_str = ''.join(final_cipher)

    final_cipher_ascii = binary_to_ascii(final_cipher_str)
    
    return final_cipher_ascii

def decryption(final_cipher):
    enc_to_binary = str_to_bin(final_cipher)

    # Membuat 16 putaran keys
    round_keys = generate_round_keys(key_to_bin_dec())
    
    # Initial Permutation
    ip_dec_result_str = initial_permutation(enc_to_binary)
    
    lpt = ip_dec_result_str[:32] # Left Part
    rpt = ip_dec_result_str[32:] # Right Part

    for round_num in range(16):
        # Expansion 32 bit -> 48 bit
        expanded_result = [rpt[i - 1] for i in e_box_table]
        expanded_result_str = ''.join(expanded_result)

        # Mengambil Keys dengan urutan terbalik
        round_key_str = round_keys[15-round_num]
    
        xor_result_str = ''
        for i in range(48):
            xor_result_str += str(int(expanded_result_str[i]) ^ int(round_key_str[i]))
    
        # Membagi menjadi 8 grup berisi 6 bit
        six_bit_groups = [xor_result_str[i:i+6] for i in range(0, 48, 6)]
    
        subtitution_result = ''
    
        for i in range(8):
            # row_bits berisi bit awal dan terakhir
            row_bits = int(six_bit_groups[i][0] + six_bit_groups[i][-1], 2)

            # col_bits berisi 4-bit yang ada di tengah
            col_bits = int(six_bit_groups[i][1:-1], 2)
    
            s_box_value = subtitution_box[i][row_bits][col_bits]
            subtitution_result += format(s_box_value, '04b')
    
        p_box_result = [subtitution_result[i - 1] for i in p_box_table]
    
        lpt_list = list(lpt)
    
        # XOR Left Part dan Hasil Permutasi
        new_rpt = [str(int(lpt_list[i]) ^ int(p_box_result[i])) for i in range(32)]

        new_rpt_str = ''.join(new_rpt)
    
        lpt = rpt
        rpt = new_rpt_str
    
    final_result = rpt + lpt

    # final permutation (IP-1)
    final_cipher = [final_result[ip_inverse_table[i] - 1] for i in range(64)]

    final_cipher_str = ''.join(final_cipher)

    final_cipher_ascii = binary_to_ascii(final_cipher_str)

    return final_cipher_ascii

def split_string(string):
    return [string[i:i + 8] for i in range(0, len(string), 8)]


# Global Variable for RSA

private_key = {'d': 173, 'n': 323}
public_key = {'e': 5, 'n': 323}
pka_public_key = {'e': 3, 'n': 667}
client_public_key = {
    'pka': {'e': 3, 'n': 667},
}


# RSA Algorithm

def signature_encrypt(message):
    d = private_key['d']
    n = private_key['n']

    c = pow(message, d) % n

    return c

def signature_decrypt(ciphertext, identity):
    e = client_public_key[identity]['e']
    n = client_public_key[identity]['n']

    m = pow(ciphertext, e) % n
    return m

def rsa_string_encoder(string, target_identity):
    encoded = []
    for letter in string:
        encoded.append(rsa_encrypt(ord(letter), target_identity))
    return encoded

def rsa_string_decoder(encoded):
    s = ''
    for num in encoded:
        s += chr(rsa_decrypt(num))
    return s

def rsa_encrypt(message, target_identity):
    e = client_public_key[target_identity]['e']
    n = client_public_key[target_identity]['n']

    c = pow(message, e) % n

    return c

def rsa_decrypt(ciphertext):
    d = private_key['d']
    n = private_key['n']

    m = pow(ciphertext, d) % n

    return m

def key_des_decrypt(encrypted, identity):
    message_decrypted = []
    for num in encrypted:
        message_decrypted.append(rsa_decrypt(num))
    
    s = ''
    for num_signature in message_decrypted:
        s += chr(signature_decrypt(num_signature, identity))

    return s

def get_public_key(identity):
    host = socket.gethostname()
    port = 6780

    pka_socket = socket.socket()
    pka_socket.connect((host, port))

    pka_socket.send(identity.encode())

    public_key = pka_socket.recv(1024).decode()

    if (public_key != "bad"):

        public_key_dict_encrypted = json.loads(public_key)
        e = signature_decrypt(public_key_dict_encrypted['e'], 'pka')
        n = signature_decrypt(public_key_dict_encrypted['n'], 'pka')

        client_public_key[identity] = {}

        client_public_key[identity]['e'] = e
        client_public_key[identity]['n'] = n

        print(f"Public Key {identity}:")
        print(f"e: {e}")
        print(f"n: {n} \n")
        pka_socket.close()
        return e, n
    
    print(public_key)
    pka_socket.close()

    return 0

def handshake_initiator(target_identity, client_socket, know=False):
    global des_key
    my_identity = "clientsock"
    n1 = "test1"

    print(f"From: {my_identity}")
    print(f"identifier: {n1}")

    my_identity_encrypted = rsa_string_encoder(my_identity, target_identity)

    if know == True:

        key_permission = rsa_string_encoder("Req keyq", target_identity)
        data_to_send = [key_permission, my_identity_encrypted]
        client_socket.send(json.dumps(data_to_send).encode())

        data = client_socket.recv(1024).decode()
        data_rcv = json.loads(data)

        des_key = key_des_decrypt(data_rcv, target_identity)

        return

    
    n1_encrypted = rsa_string_encoder(n1, target_identity)

    data_to_send = [my_identity_encrypted, n1_encrypted]

    client_socket.send(json.dumps(data_to_send).encode())

    print("Data ID dan n1 telah dikirim \n")

    data = client_socket.recv(1024).decode()

    print("Data n1 dan n2 telah diterima")

    data_rcv = json.loads(data)

    data_rcv_n1 = rsa_string_decoder(data_rcv[0])
    data_rcv_n2 = rsa_string_decoder(data_rcv[1])

    print(f"n1 diterima: {data_rcv_n1}")
    print(f"n2 diterima: {data_rcv_n2}")

    if n1 == data_rcv_n1:
        print("n1 sesuai")
        n2 = rsa_string_encoder(data_rcv_n2, target_identity)
        client_socket.send(json.dumps([n2]).encode())

        print("Data n2 telah dikirim kembali \n")

        data = client_socket.recv(1024).decode()
        data_rcv = json.loads(data)
        des_key = key_des_decrypt(data_rcv, target_identity)

        print(f"Key DES diterima: {des_key}\n")
        print("Percakapan dapat dimulai")


# Socket Program

def client_program():
    host = socket.gethostname()
    port = 6789

    client_socket = socket.socket()
    client_socket.connect((host, port))

    identity = input("Target Conversation: ")
    if identity not in client_public_key:
        get_public_key(identity)
        handshake_initiator(identity, client_socket)
    else:
        handshake_initiator(identity, client_socket, know=True)


    message = input(" -> ")

    while message.lower().strip() != 'bye':

        full_message = ''
        split_message_enc = split_string(message)
        for string in split_message_enc:
            enc = encryption(string)
            full_message += enc
        client_socket.send(full_message.encode())


        data = client_socket.recv(1024).decode()
        full_message = ''
        split_message_dec = split_string(data)
        for string in split_message_dec:
            dec = decryption(string)
            full_message += dec

        print('Received from server: ' + full_message)

        message = input(" -> ")

    client_socket.close()


if __name__ == '__main__':
    client_program()

