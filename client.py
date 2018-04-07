# Controller software which interacts with IoT devices to securely collect user information
# and write updates to each device.

import sys
import socket
import hashlib
import hmac
import random
import string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import time
import datetime
import os.path

BLOCK_SIZE = 1024

# Function used to encrypt every message sent subsequently after the first message from the client
def encrypt_message(message):

    global cipher
    global cipher_function

    if cipher == "aes128" or cipher == "aes256":
        #message = message.encode("UTF-8")

        # Initialize the encryptor
        encryptor = cipher_function.encryptor()

        length = 16 - (len(message) % 16)
        message += bytes([length]) * length

        # Encrypt the padded message
        encrypted_message = encryptor.update(message) + encryptor.finalize()

        return encrypted_message

    else:

        # Null cipher so return message
        return message

# Similar as encrypt but for decryption
def decrypt_message(message):

    global cipher
    global cipher_function

    if cipher == "aes128" or cipher == "aes256":

        # Initialize decryptor
        decryptor = cipher_function.decryptor()

        decrypted_data = decryptor.update(message) + decryptor.finalize()

        if message != b'':
            decrypted_data = decrypted_data[:-decrypted_data[-1]]

        try:
            return decrypted_data.decode("UTF-8")

        except UnicodeDecodeError as e:
            sys.stderr.write(current_time() + " Unicode decode error.")

    else:

        # Null cipher so return message
        return message.decode("UTF-8")


# Responsible for reading the file from the server to standard output
def read_file(command, filename, client_socket):

    try:
        message = encrypt_message((command + ":" + filename).encode("UTF-8"))
        client_socket.sendall(message)

        # Receive server acknowledgement and file size
        ack_size = client_socket.recv(BLOCK_SIZE)
        ack_size = decrypt_message(ack_size)

        ack_size = ack_size.split(":")

        ack = ack_size[0]

        sys.stderr.write(current_time() + " " + ack + "\n")

        # Check if file size received
        if len(ack_size) == 2:

            size_of_file = ack_size[1]
            size_of_file_counter = int(size_of_file)

            file_output = bytearray()

            # Keep reading chunk data from the server and writing it to stdout
            while size_of_file_counter > 0:

                # We don't wanna read in 1024 if there is less than 1024 bytes left
                if size_of_file_counter < BLOCK_SIZE:

                    data_chunk = client_socket.recv(BLOCK_SIZE)
                    data_chunk = decrypt_message(data_chunk)
                    data_chunk = data_chunk.encode("UTF-8")

                else:

                    data_chunk = client_socket.recv(BLOCK_SIZE)
                    data_chunk = decrypt_message(data_chunk)
                    data_chunk = data_chunk.encode("UTF-8")

                # Add chunk to a byte array
                file_output.extend(data_chunk)

                # If nothing is read, break out of loop
                if not data_chunk:
                    break

                # Decrease size counter for every 1024 bytes read
                size_of_file_counter -= len(data_chunk)

            # Store collected information to a file
            with open("personal_information.txt", "wb") as file:

                file.write(file_output)

            file.close()

            # Write read data from server to standard output
            print(current_time() + " Read information: \n")
            sys.stdout.write(file_output.decode(encoding='UTF-8'))
            print(current_time() + " Collected IoT Information has been stored in a database.")

    except socket.error as e:

        sys.stderr.write(current_time() + " Server connection closing...\n")
        quit()


# Responsible for reading a file from standard input and sending (writing) it to the server, chunk by chunk
# whilst not reading into memory
def update_file(command, client_socket, patch_file):

    global cipher

    try:

        message = encrypt_message((command + ":" + patch_file + ".patch").encode("UTF-8"))
        client_socket.sendall(message)

        # Receive server acknowledgement
        ack = client_socket.recv(BLOCK_SIZE)
        ack = decrypt_message(ack)

        sys.stderr.write(current_time() + " " + ack + "\n")

        # Make sure that if the cipher used is not the null cipher, we read in 1023 bytes so as to always
        # pad the content when encrypting and depad when decrypting

        if cipher != "null":
            #content = sys.stdin.buffer.read(BLOCK_SIZE - 1)

            file = open(patch_file + ".patch", "rb")
            try:
                content = file.read(BLOCK_SIZE - 1)

            except:

                sys.stderr.write(current_time() + " File read error. Client connection closing...\n")
                quit()


            # This will return a block size that is a multiple of 16 bytes
            content = encrypt_message(content)

        else:
            #content = sys.stdin.buffer.read(BLOCK_SIZE)


            file = open(patch_file + ".patch", "rb")
            try:
                content = file.read(BLOCK_SIZE)


            except:

                sys.stderr.write(current_time() + " File read error. Client connection closing...\n")
                quit()
                

        # While the content length read in from stdin is a 1024, keep getting chunk and sending it to the server
        while len(content) == BLOCK_SIZE:

            client_socket.sendall(content)

            if cipher != "null":
                #content = sys.stdin.buffer.read(BLOCK_SIZE - 1)

                try:
                    content = file.read(BLOCK_SIZE - 1)


                except:

                    sys.stderr.write(current_time() + " File read error. Client connection closing...\n")
                    quit()
                
                content = encrypt_message(content)

            else:
                #content = sys.stdin.buffer.read(BLOCK_SIZE)


                try:
                    content = file.read(BLOCK_SIZE)


                except:

                    sys.stderr.write(current_time() + " File read error. Client connection closing...\n")
                    quit()
                

        # Send last block (if any) that is less than a 1024 bytes
        client_socket.sendall(content)

        
        file.close()

    except socket.error as e:

        sys.stderr.write(current_time() + " Client connection closing...\n")
        quit()


# Creates a hex digest response of the random string challenge obtained by the server
def challenge_response(secret_key, challenge):

    # Encode the key into bytes
    secret_key = secret_key.encode("UTF-8")

    # Takes random challenge string (in bytes) concatenates it with secret key and gets the hash using sha256 hmac
    hmac_hash = hmac.new(secret_key, challenge, digestmod=hashlib.sha256)

    # Get the hash digest
    hash_digest = hmac_hash.hexdigest()

    return hash_digest


# Generates a random string (used for generating the nonce)
def string_generator():

    return ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(16))


# Prompts the controller for read or write
def device_choice():

    valid_device = False

    print("Currently active devices:\n")

    with open("active_devices.txt") as file:

        content = file.readlines()

    file.close()

    counter = 1
    for i in content:

        print(str(counter) + " " + i)

        counter += 1


    while (valid_device == False):

        print("\nWhich device would you like to interact with?")
        device_number = input()

        try:
            device = content[int(device_number) - 1]

            valid_device = True

        except:

            sys.stderr.write(current_time() + " Invalid choice. Please try again.\n")

    return device


# Takes the ID and Firmware version response of the IoT device and checks if it is up to date
def check_firmware(identity_response):

    # Set update required to false.
    update_required = 0

    device_id = identity_response[0]
    firmware_version = float(identity_response[1])

    with open("current_firmware_versions") as file:

        content = file.readlines()

    file.close()

    matching_device = ""

    for i in content:

        i = i.split()

        if i[0] == device_id:
            matching_device = i
            break

    latest_firmware_version = float(matching_device[1])

    # If firmware version is not latest, update the device.
    if firmware_version < latest_firmware_version:

        update_required = 1

        print(current_time() + " " + device_id + " required an update.")

        return update_required, latest_firmware_version

    else:

        print(current_time() + " " + device_id + " is up to date.")

        return update_required, latest_firmware_version


# Get the current time
def current_time():

    # Current time the connection is initiated
    curr_time = datetime.datetime.now().time()
    return curr_time.strftime("%H:%M:%S" + ":")


if __name__ == "__main__":

    if len(sys.argv) != 3:
        sys.stderr.write(current_time() + " Wrong number of arguments provided\n")
        sys.stderr.write(current_time() + " USAGE: 'python client.py [cipher] [key]'\n")
        quit()

    cipher = sys.argv[1]
    key = sys.argv[2]

    


#login system, hashes to hashfile.txt
    
    if(os.path.isfile("hashfile.txt")):
        with open ("hashfile.txt") as f:

            filehash = f.readline()

            counter = 0

            # Prompt for username and password
            while(True):

                usrname = input("Enter Username:  ")
                psword = input("Enter Password:  ")

                #Hash username and password
                m = hashlib.sha256()
                m.update((usrname + psword).encode('utf-8'))

                
                # Check if hash digest matches the one in the hashfile
                if(str(m.hexdigest()) == str(filehash)):
                    break
                
                print("Wrong username or password")

                counter = counter + 1
                if(counter == 3):
                    print("Too many attempts...")
                    quit()

    else:

        # Set a username and password
        usrname = input("Set Username:  ")
        psword = input("Set Password:  ")
        m = hashlib.sha256()
        m.update((usrname + psword).encode('utf-8'))
        m.hexdigest()

        with open("hashfile.txt", 'a') as f:
            f.write(m.hexdigest())


    device = device_choice()

    device = device.split()        

    print(device)


    print("Would you like to do a read or a update?")
    command = input()
    

    if not (command == "read" or command == "update"):
        sys.stderr.write(current_time() + " Error: wrong operation given. Operation has to be either read or update\n")
        quit()


    hostname = device[1]
    port = device[2]

    # Convert port string to int
    port = int(port)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    client_socket.connect((hostname, port))

    # Generate a nonce
    nonce = string_generator()

    # Set up the IV and session-key
    init_vector = hashlib.sha256((key + nonce + "IV").encode("UTF-8"))

    # IV has to be 16 bytes
    init_vector = init_vector.hexdigest()
    init_vector = init_vector[:16]

    session_key = hashlib.sha256((key + nonce + "SK").encode("UTF-8"))

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

    # Send the cipher and nonce to the server
    client_socket.sendall((cipher + ":" + nonce).encode("UTF-8"))

    # Receive server acknowledgement
    ack = client_socket.recv(BLOCK_SIZE)
    ack = decrypt_message(ack)
    sys.stderr.write(current_time() + " " + ack + "\n")

    # Get the random string challenge from the server and create a response
    challenge = client_socket.recv(BLOCK_SIZE)
    challenge = challenge.strip()

    challenge = decrypt_message(challenge)

    digest_response = challenge_response(key, challenge.encode("UTF-8"))
    digest_response = encrypt_message(digest_response.encode("UTF-8"))

    # Send the response back to the server
    client_socket.sendall(digest_response)

    # Receive authentication success or failure
    authentication_response = client_socket.recv(BLOCK_SIZE)

    authentication_response = decrypt_message(authentication_response)

    sys.stderr.write(current_time() + " " + authentication_response + "\n")

    identity_request = "identity_request"
    identity_request = encrypt_message(identity_request.encode("UTF-8"))
    client_socket.sendall(identity_request)

    # IoT device sends back its device ID and firmware version
    identity_response = client_socket.recv(BLOCK_SIZE)
    identity_response = decrypt_message(identity_response)

    identity_response = identity_response.split("_")


    # Send the filename and the operation we wish to do upon it to the server
    if command == "update":


        update_firmware = check_firmware(identity_response)

        if len(update_firmware) == 2:

            update_required = update_firmware[0]
            latest_firmware_version = update_firmware[1]

        # If an update is required, update the device by sending it the update patch file
        if update_required:

            device_id = identity_response[0]
            patch_file = str(device_id) + "_" + str(latest_firmware_version)

            print(current_time() + " Updating...")
            update_file(command, client_socket, patch_file)

        # Inform IoT device that it is up to date
        else:

            message = encrypt_message(("up_to_date" + ":" + "0").encode("UTF-8"))
            client_socket.sendall(message)
            quit()


    else:

        filename = "collected_information.txt"
        read_file(command, filename, client_socket)

    time.sleep(0.1)
    # Final message before closing down the connection (Initiated on a successful read or write.)
    final_message = client_socket.recv(BLOCK_SIZE)

    final_message = decrypt_message(final_message)

    sys.stderr.write(current_time() + " " + final_message + "\n")

    client_socket.close()