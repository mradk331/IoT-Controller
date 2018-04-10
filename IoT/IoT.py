# Authors: Rumen Kasabov, Michael Radke

# IoT device software used for transferring private information and receiving updates
# to/from a centralized controller.

import sys
import socket
import hashlib
import random
import string
import hmac
import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import  datetime


BLOCK_SIZE = 1024

def current_device(port):

    global devices

    current_IoT_device = devices[str(port)]

    print(devices[str(port)])

    return current_IoT_device

def update_device(port, filename):

    global devices

    print(current_time() + ": " + "Updating the IoT device.")

    # Remove .patch from new device ID
    filename = filename.split(".patch")

    devices[str(port)] = filename[0]


def request(client_socket, port):

    global devices

    identity_request = client_socket.recv(BLOCK_SIZE)
    identity_request = decrypt_message(identity_request)

    if identity_request == "identity_request":

        current_IoT_device = current_device(port)
        current_IoT_device = encrypt_message(current_IoT_device)

        client_socket.sendall(current_IoT_device)


    # Receive the filename and operation
    fileop = client_socket.recv(BLOCK_SIZE)

    fileop = decrypt_message(fileop)

    fileop = fileop.strip()


    fileop = fileop.split(":")

    operation = fileop[0]
    filename = fileop[1]

    if operation == "up_to_date":

        up_to_date_device = devices[str(port)]
        up_to_date_device = up_to_date_device.split("_")
        print(current_time() + ": IoT device " + up_to_date_device[0] + " is up to date.")

        return

    sys.stdout.write(
        current_time() + " command: " + operation + " filename: " + filename + "\n")

    # Check if operation and filename are valid
    if operation == "read":

        if not os.path.isfile(filename):

            sys.stdout.write(
                current_time() + " Status: error, file client is trying to read does not exist\n")

            message = encrypt_message(("Error, the file " + filename
                                       + " you are trying to read does not exist. Disconnecting..."))
            client_socket.sendall(message)
            client_socket.close()

        else:

            # Send file-size to client
            file_size = os.stat(filename).st_size
            file_size = str(file_size)

            message = encrypt_message(("Success, read operation proceeding." + ":" + file_size))
            client_socket.sendall(message)

            # Delay sending the file chunks so as to not send the above success, filesize along with
            # a part of a file chunk
            time.sleep(0.1)

            data_exchange(client_socket, operation, filename)

    elif operation == "update":

        curr_device = current_device(port)

        # Update the device list
        update_device(port, filename)
        version = filename.split(".patch")

        if curr_device != version[0]:

            print(current_time() + " " + curr_device + " has been updated to " + version[0])

        else:

            print(current_time() + " " + curr_device + " is up to date.")



        time.sleep(0.1)
        # Indicate success
        message = encrypt_message("Success, write operation proceeding.")
        client_socket.sendall(message)

        time.sleep(0.2)

        data_exchange(client_socket, operation, filename)

    else:

        sys.stdout.write(
            current_time() + " Status: error, operation request: " + operation + " on file " + filename + "\n")

        # Operation does not exist
        message = encrypt_message(("Error, operation " + operation + " you are trying to perform on " + filename + " does not exist. Disconnecting..."))
        client_socket.sendall(message)

        client_socket.close()


# Function where the data transfers occur depending on if the operation is a read or a write
def data_exchange(client_socket, operation, filename):

    if operation == "read":

        # Open the file, read chunks, encrypt and send them to the client
        file = open(filename, 'rb')
        line = file.read(BLOCK_SIZE - 1)

        # While there is a line read from the file, keep sending it as a chunk to the client
        while line:

            message = encrypt_message(line.decode("UTF-8"))
            client_socket.sendall(message)

            # Read next line in file
            line = file.read(BLOCK_SIZE - 1)

        # Close file
        file.close()

        time.sleep(.2)

        sys.stdout.write(
            current_time() + " Status: operation successful\n")

        message = encrypt_message((operation + " operation successful. Disconnecting..."))
        client_socket.sendall(message)
        client_socket.close()

    # Otherwise we write to server from client side
    else:

        file_size = 0

        # Get hard drive statistics (such as disk space) from current directory
        stats = os.statvfs('/')

        # disk size in bytes = (block size of file system * available number of blocks to the user) / 1024
        # This is the disk size for the current directory
        disk_size = (stats.f_frsize * stats.f_bavail) / BLOCK_SIZE

        # We open file with filename and keep writing received chunks of data to it
        with open(filename, 'wb') as file:

            write_chunk = client_socket.recv(BLOCK_SIZE)
            decrypt_chunk = decrypt_message(write_chunk)

            # Keep writing chunks that are the block size
            while len(write_chunk) == BLOCK_SIZE:

                chunk_length = len(write_chunk)

                file_size += chunk_length

                # Write to file on disk
                if file_size < disk_size:

                    file.write(decrypt_chunk.encode("UTF-8"))

                    write_chunk = client_socket.recv(BLOCK_SIZE)
                    decrypt_chunk = decrypt_message(write_chunk)

                # If the file we are reading in becomes larger
                # than or equal to the available disk size, indicate error and disconnect
                else:
                    sys.stderr.write(
                        current_time() + " Status: error, client trying to write a file that is larger "
                                         "than the available disk size.\n")

                    message = encrypt_message("Error, you are trying to upload a file that "
                                              "is larger than the available server disk size. Disconnecting...")

                    client_socket.sendall(message)

                    client_socket.close()

            if file_size < disk_size:

                file.write(decrypt_chunk.encode("UTF-8"))

                # Can't send too fast to client - hence delay
                time.sleep(.1)

                sys.stdout.write(current_time() + " Status: operation successful\n")
                message = encrypt_message((operation + " operation successful. Disconnecting..."))
                client_socket.sendall(message)
                client_socket.close()



            # If the file we are reading in becomes larger
            # than or equal to the available disk size, indicate error and disconnect
            else:
                sys.stderr.write(
                    current_time() + " Status: error, client trying to write a file that is larger "
                                     "than the available disk size.\n")

                message = encrypt_message("Error, you are trying to upload a file that "
                                          "is larger than the available server disk size. Disconnecting...")

                client_socket.sendall(message)

                client_socket.close()

        file.close()


# Function used to encrypt every message sent subsequently after the first message to the client
def encrypt_message(message):

    global cipher
    global cipher_function

    if cipher == "aes128" or cipher == "aes256":

        message = message.encode("UTF-8")

        # Initialize the encryptor
        encryptor = cipher_function.encryptor()

        # Pad the message to a multiple of 16 based on the length modulo 16 subtracted by 16
        length = 16 - (len(message) % 16)
        message += bytes([length]) * length

        # Encrypt the padded message
        encrypted_message = encryptor.update(message) + encryptor.finalize()

        return encrypted_message

    else:

        # Null cipher so return message
        return message.encode("UTF-8")


def decrypt_message(message):

    global cipher
    global cipher_function

    if cipher == "aes128" or cipher == "aes256":

        # Initialize decryptor
        decryptor = cipher_function.decryptor()

        # Decrypt the message
        decrypted_data = decryptor.update(message) + decryptor.finalize()

        # If the message is not an empty, remove padding by slicing away the end padding in
        # decrypted data. [-1] returns the size of the padding.
        if message != b'':

            decrypted_data = decrypted_data[:-decrypted_data[-1]]
        try:

            return decrypted_data.decode("UTF-8")

        except UnicodeDecodeError as e:
            sys.stderr.write("Unicode decode error")

    else:

        # Null cipher so return message
        return message.decode("UTF-8")


# Generates a random string
def string_generator():

    return ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(32))

# Get the current time
def current_time():

    # Current time the connection is initiated
    curr_time = datetime.datetime.now().time()
    return curr_time.strftime("%H:%M:%S")


# Function responsible for sending a random string challenge, receiving the response from the client,
# and authenticating the client to move onto the response request from client
def authentication(secret_key, client_socket):

    authenticated = False

    # Generate a 32 byte random string challenge
    random_string = string_generator()

    # Encrypt the random string message
    encrypted_message = encrypt_message(random_string)

    # Encode the secret key
    secret_key = secret_key.encode("UTF-8")

    # Delay sending the challenge by .2 seconds in the case of receiving the challenge with the previous success ack
    time.sleep(0.2)

    # Send the random string challenge to the client
    client_socket.sendall(encrypted_message)

    # Receive an encrypted SHA256 HMAC hexadecimal digest challenge response by the client
    response = client_socket.recv(BLOCK_SIZE)

    # Decrypt the response
    response = decrypt_message(response)

    # Strip of any special characters
    response = response.strip()

    # We hash the server secret key with the same random_string and obtain the hexadecimal digest
    secret_key_hash = hmac.new(secret_key, msg=random_string.encode("UTF-8"), digestmod=hashlib.sha256)

    # Obtain hex-digest
    secret_key_digest = secret_key_hash.hexdigest()

    # If the digest we computed is the same as the one provided by the response of the client, then the client has the
    # correct secret key
    if secret_key_digest == response:

        # Send success to client
        success_message = encrypt_message("Successfully authenticated")

        client_socket.sendall(success_message)

        # Client is now authenticated
        authenticated = True

        return authenticated

    else:

        failure_message = encrypt_message("Error: Wrong key. Disconnecting...")

        client_socket.sendall(failure_message)

        # Disconnect the client
        client_socket.close()

        return authenticated

if __name__ == "__main__":

    devices = {"9000" : "Webcam_1.1", "9001" : "Toaster_2.9", "9002" : "TV_1.12", "9003" : "Refrigerator_5.9", "9004" : "Thermostat_4.3"}

    HOST = "localhost"

    if len(sys.argv) != 3:
        sys.stdout.write("Error: Wrong number of arguments provided\n")
        sys.stdout.write("USAGE: 'python server.py [port] [key]'\n")
        quit()

    port = sys.argv[1]
    key = sys.argv[2]

    sys.stdout.write("Listening on port: " + port + "\n")
    sys.stdout.write("Using secret key: " + key + "\n")

    # Convert port string to int
    port = int(port)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the source hostname and the source port number
    server_socket.bind((HOST, port))

    # Listen to incoming messages
    server_socket.listen(5)

    # We keep looping and accepting client connection
    while 1:

        (client_socket, client_address) = server_socket.accept()

        data = client_socket.recv(BLOCK_SIZE)

        data = data.decode("UTF-8")

        data = data.split(":")

        for i in data:
            print("DATA : " + i)

        if len(data) != 2:
            sys.stdout.write(current_time() + " Error: Cipher or nonce not provided. Disconnecting client.\n")

            client_socket.sendall("Error: cipher or nonce not provided. Disconnecting...".encode("UTF-8"))
            client_socket.close()
        else:
            cipher = data[0].lower()
            nonce = data[1]

            # Set up the IV and session-key
            init_vector = hashlib.sha256((key + nonce + "IV").encode("UTF-8"))

            init_vector = init_vector.hexdigest()

            session_key = hashlib.sha256((key + nonce + "SK").encode("UTF-8"))

            sys.stdout.write(current_time() + ":" + " new connection from " + str(client_address)
                             + " cipher=" + cipher + "\n")

            sys.stdout.write(current_time() + ":" + " nonce=" + nonce + "\n")
            sys.stdout.write(current_time() + ":" + " IV=" + init_vector + "\n")
            sys.stdout.write(current_time() + ":" + " SK=" + session_key.hexdigest() + "\n")

            # IV has to be 16 bytes
            init_vector = init_vector[:16]

            # Check if incorrect cipher was provided
            if cipher != "aes128" and cipher != "aes256" and cipher != "null":

                sys.stdout.write(current_time() + " Status: error, invalid cipher provided. Disconnecting client.\n")

                client_socket.sendall(("Error " + cipher + " is not supported. Disconnecting...").encode("UTF-8"))
                client_socket.close()

            else:

                # If cipher used is aes128 we strip the session key to 16 bytes and pass that into the cipher function
                if cipher == "aes128":

                    session_key = session_key.hexdigest()
                    session_key = session_key[:16]

                    # Set up the cipher
                    cipher_function = Cipher(algorithms.AES(session_key.encode("UTF-8")), modes.CBC(init_vector.encode("UTF-8")),
                                             backend=default_backend())

                # Otherwise if the cipher is aes256 we strip to 32 bytes
                elif cipher == "aes256":

                    session_key = session_key.hexdigest()
                    session_key = session_key[:32]
                    cipher_function = Cipher(algorithms.AES(session_key.encode("UTF-8")), modes.CBC(init_vector.encode("UTF-8")),
                                             backend=default_backend())

                # Indicate success to user
                success = encrypt_message("Successfully received cipher.")
                client_socket.sendall(success)

                # Authenticate the client
                authenticated = authentication(key, client_socket)

                # If the client is authenticated, get the file request
                if authenticated:

                    request(client_socket, port)

                else:
                    sys.stdout.write(
                        current_time() + " Status: error, client was not authenticated. Secret keys not matching.\n")
