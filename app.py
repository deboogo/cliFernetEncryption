from cryptography.fernet import Fernet, InvalidToken
import os
import sys
import argparse
import base64
import uuid


def key_generation():
    """ 
    generates and saves an encryption key using fernet with a random name
    """
    key = Fernet.generate_key()
    random_name = uuid.uuid4().hex.upper()[0:6]
    # Save the key to a file
    with open(f"{random_name}.key", 'wb') as filekey:
        filekey.write(key)
    print(f"Saving key as {random_name}.key")

def load_key(secret_key):
    """ 
    load key function essentially just reads the key file and makes it usable for other portions of the program
    """
    return open(secret_key, 'rb').read()

def file_encrypt(filename, key):
    """
    takes given file from user and returns encrypted

    Args:
        filename 
    
    Returns:
        encrypted file
    
    Raises:
        File not found message
    """


    fernet = Fernet(key)
    if not os.path.isfile(filename):
                raise FileNotFoundError(f"File {filename} not found.")
        
    # Read user file 
    with open(filename, 'rb') as file:
        original = file.read()
    
    # Encrypt the file using fernet
    encrypted = fernet.encrypt(original)

    # opening the file in write mode and 
    # writing the encrypted data
    with open(filename, 'wb') as encrypted_file:
        encrypted_file.write(encrypted)
    
    print(f"Encrypting file: {filename}")


def file_decrypt(filename, key):
    """
    takes filename and decrypts

    Args:
        filename 
    
    Returns:
        decrypted file
    
    Raises:
        File not found message
    """
    # load key
    fernet = Fernet(key)

    if not os.path.isfile(filename):
            raise FileNotFoundError(f"File {filename} not found.")
    
    # Read user file 
    with open(filename, 'rb') as file:
        encrypted = file.read()
    
    try:
        # decrypt the file using fernet
        decrypted = fernet.decrypt(encrypted)

        # opening the file in write mode and 
        # writing the decrypted data
        with open(filename, 'wb') as decrypted_file:
            decrypted_file.write(decrypted)
        
        print(f"Decrypting file: {filename}")
    except InvalidToken:
        print(f"Failed to decrypt {filename}. Is this file encrypted with Fernet?")
    except Exception as e:
        print(f"An error occured: {e}")
        print({e})


def is_valid_key(key):
    try:
        # Try decoding the key from Base64 to check length and validity
        decoded_key = base64.urlsafe_b64decode(key)
        return len(decoded_key) == 32
    except (TypeError, ValueError):
        # If decoding fails or the length is incorrect, it's an invalid key
        print("Key is invalid")
        return False

    
def main():
    # sets up the argparser object that allows for command line arguments to be passed. 
    # the help message shows up with --help or -h
    parser = argparse.ArgumentParser(description="Encrypt and decrypt files using Fernet symmetric encryption")

    # add parser arguments for file and keyfile
    parser.add_argument("file_name", type=str, nargs="?", help="The path to the file to encrypt or decrypt")
    parser.add_argument("key_file", type=str, nargs="?", help="The path to the secret key")

    # generate key
    parser.add_argument(
        "-g", "--generate", action="store_true", help="Generate a Fernet secret key"
    )

    # mutually exclusive group so that either encryption or decryption can happen
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-d", "--decrypt", action="store_true", help="Decrypts a given file"
    )
    group.add_argument(
        "-e", "--encrypt", action="store_true", help="Encrypts a given file"
    )

    # Parse the arguments
    args = parser.parse_args()
    if args.generate:
         key_generation()
         sys.exit(0)

    if (args.encrypt or args.decrypt) and not (args.file_name and args.key_file):
        print("You must provide a keyfile (can be generated with '-g' or '--generate' and file to encrypt or decrypt.")
        sys.exit(1)
    
    if args.key_file:
        key = load_key(args.key_file)
        if not is_valid_key(key):
            print("Invalid key. Exiting.")
            sys.exit(1)

    # Handle encryption and decryption
    if args.encrypt:
        file_encrypt(args.file_name, key)
    elif args.decrypt:
        file_decrypt(args.file_name, key)


if __name__ == "__main__":
    main()