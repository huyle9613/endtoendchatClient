import os
import json
from cryptography.hazmat.primitives import hashes, hmac, padding
padder = padding.PKCS7(256).padder()
unpadder = padding.PKCS7(256).unpadder()

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encryption(message, public):
    backend = default_backend()
    
    f = open(public, 'rb') # open the public key pem file
    rsa_public = serialization.load_pem_public_key(f.read(), backend=backend) # import the key to RSA

    padded_message = padder.update(message.encode('utf-8'))
    padded_message += padder.finalize()
    
    aes_key = os.urandom(32) # generate AES 256-bit key
    iv = os.urandom(16) # generate the IV
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=backend)
    aes_object = cipher.encryptor() # create AES object
    ciphertext = aes_object.update(padded_message) + aes_object.finalize() # encrypt the message using AES
    
    hmac_key = os.urandom(32) #256-bit key used for HMAC
    hmac_object = hmac.HMAC(hmac_key, hashes.SHA256(), backend=backend) # create HMAC object using HMAC key and SHA256
    hmac_object.update(ciphertext)
    tag = hmac_object.finalize() # create the integrity tag
    
    concatenated_key = aes_key + hmac_key # concatenate the keys (AES and HMAC keys)
    # encrypt the concatenated key
    rsa_cipher = rsa_public.encrypt(
        concatenated_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # create a JSON output
    json_object = {'RSA_cipher': rsa_cipher, 'AES_cipher': ciphertext, 'IV': iv, 'tag': tag}
    return json_object

test = encryption("brogrammers", "public.pem")

def decryption(json_object, private):
    backend = default_backend()
    
    f = open(private, 'rb') # open the private key pem file
    rsa_private = serialization.load_pem_private_key(f.read(), password=None, backend=backend) # import the private key to RSA object
    
    # decrypt the RSA cipher concatenate keys
    concatenated_key = rsa_private.decrypt(
        json_object['RSA_cipher'],
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # slit the concatenated key into half for AES key and HMAC key
    aes_key = concatenated_key[:len(concatenated_key)//2]
    hmac_key = concatenated_key[len(concatenated_key)//2:]
    
    # recreate the tag to compare with the original tag for integrity
    hmac_object = hmac.HMAC(hmac_key, hashes.SHA256(), backend=backend)
    hmac_object.update(json_object['AES_cipher'])
    tag = hmac_object.finalize()
    if(tag != json_object['tag']):
        return "failure"
    else:
        # descrypt the message after verify the tag
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(json_object['IV']), backend=backend)
        aes_object = cipher.decryptor()
        padded_message = aes_object.update(json_object['AES_cipher']) + aes_object.finalize()
        message = unpadder.update(padded_message)
        plaintext = (message + unpadder.finalize()).decode('utf-8')
        return plaintext
    

message = decryption(test, "private.pem")
print(message)