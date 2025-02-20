import os
import boto3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Initialize the S3 client
s3_client = boto3.client('s3')

# Function to encrypt a file using AES-256-GCM
def encrypt_file(input_bucket, input_key, output_bucket, output_key, public_key):
    # Generate AES-256 key (32 bytes)
    aes_key = os.urandom(32)
    
    # Generate a random nonce for AES-GCM (12 bytes)
    nonce = os.urandom(12)
    
    # Download the file from S3
    file_data = s3_client.get_object(Bucket=input_bucket, Key=input_key)['Body'].read()

    # Encrypt the file data with AES-256-GCM
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(file_data) + encryptor.finalize()
    tag = encryptor.tag
    
    # Encrypt the AES key with the asymmetric public key
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Prepare the encrypted file data (encrypted AES key, nonce, tag, and ciphertext)
    encrypted_data = encrypted_aes_key + nonce + tag + ciphertext
    
    # Upload the encrypted data to S3
    s3_client.put_object(Bucket=output_bucket, Key=output_key, Body=encrypted_data)
    
    print(f"File '{input_key}' encrypted successfully and uploaded to '{output_key}'.")

# Function to decrypt the AES key using the RSA private key
def decrypt_aes_key(encrypted_aes_key, private_key):
    # Decrypt the AES key using RSA private key
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key

# Function to decrypt a file using AES-256-GCM
def decrypt_file(input_bucket, input_key, output_bucket, output_key, private_key):
    # Download the encrypted file from S3
    encrypted_data = s3_client.get_object(Bucket=input_bucket, Key=input_key)['Body'].read()
    
    # Extract the encrypted AES key, nonce, tag, and ciphertext
    encrypted_aes_key = encrypted_data[:256]  # RSA encrypted AES key (256 bytes)
    nonce = encrypted_data[256:268]  # Nonce (12 bytes)
    tag = encrypted_data[268:284]  # Tag (16 bytes)
    ciphertext = encrypted_data[284:]  # Ciphertext

    # Decrypt the AES key with the RSA private key
    aes_key = decrypt_aes_key(encrypted_aes_key, private_key)
    
    # Decrypt the file data with AES-256-GCM
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Upload the decrypted file to S3
    s3_client.put_object(Bucket=output_bucket, Key=output_key, Body=decrypted_data)
    
    print(f"File '{input_key}' decrypted successfully and uploaded to '{output_key}'.")

# Load the RSA public or private key from S3
def load_rsa_key(key_bucket, key_key, key_type='public'):
    key_data = s3_client.get_object(Bucket=key_bucket, Key=key_key)['Body'].read()
    
    if key_type == 'public':
        key = serialization.load_pem_public_key(key_data, backend=default_backend())
    else:
        key = serialization.load_pem_private_key(key_data, password=None, backend=default_backend())
    
    return key

# Lambda handler function for encryption
def lambda_handler_encrypt(event, context):
    # Extract input and output S3 bucket and key from the event
    input_bucket = event['input_bucket']
    input_key = event['input_key']
    output_bucket = event['output_bucket']
    output_key = event['output_key']
    
    public_key_bucket = event['public_key_bucket']
    public_key_key = event['public_key_key']
    
    # Load the public key from S3
    public_key = load_rsa_key(public_key_bucket, public_key_key, key_type='public')
    
    # Encrypt the file
    encrypt_file(input_bucket, input_key, output_bucket, output_key, public_key)
    
    return {
        'statusCode': 200,
        'body': f"File '{input_key}' has been encrypted and saved to '{output_key}'."
    }

# Lambda handler function for decryption
def lambda_handler_decrypt(event, context):
    # Extract input and output S3 bucket and key from the event
    input_bucket = event['input_bucket']
    input_key = event['input_key']
    output_bucket = event['output_bucket']
    output_key = event['output_key']
    
    private_key_bucket = event['private_key_bucket']
    private_key_key = event['private_key_key']
    
    # Load the private key from S3
    private_key = load_rsa_key(private_key_bucket, private_key_key, key_type='private')
    
    # Decrypt the file
    decrypt_file(input_bucket, input_key, output_bucket, output_key, private_key)
    
    return {
        'statusCode': 200,
        'body': f"File '{input_key}' has been decrypted and saved to '{output_key}'."
    }
