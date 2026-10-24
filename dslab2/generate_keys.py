#!/usr/bin/env python3
"""
Generate ECDSA key pairs for nodes/clients and BLS keys for threshold signatures
Author: Harshith S (sharshith1312)
Course: CSE535 - Distributed Systems

ECDSA keys: Used for normal message signing (PrePrepare, ViewChange, etc.)
BLS keys: Used for threshold signature aggregation (Prepare/Commit phases)
"""

import json
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from blspy import PrivateKey, AugSchemeMPL
import secrets

def generate_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return {
        'private': base64.b64encode(private_pem).decode('utf-8'),
        'public': base64.b64encode(public_pem).decode('utf-8')
    }

def generate_bls_key():
    seed = secrets.token_bytes(32)
    sk = AugSchemeMPL.key_gen(seed)
    pk = sk.get_g1()
    
    return {
        'private': bytes(sk).hex(),
        'public': bytes(pk).hex()
    }

def generate_node_keys(num_nodes=7):
    node_keys = {}
    bls_keys = {}
    for i in range(1, num_nodes + 1):
        node_id = f'n{i}'
        print(f"Generating ECDSA keys for {node_id}...")
        node_keys[node_id] = generate_key_pair()
        print(f"Generating BLS keys for {node_id}...")
        bls_keys[node_id] = generate_bls_key()
    return node_keys, bls_keys

def generate_client_keys(client_ids):
    client_keys = {}
    for client_id in client_ids:
        print(f"Generating keys for client {client_id}...")
        client_keys[client_id] = generate_key_pair()
    return client_keys

def main():
    print("="*60)
    print("PBFT Key Generation")
    print("="*60)
    
    print("\n[1/3] Generating node ECDSA and BLS keys...")
    node_keys, bls_keys = generate_node_keys(7)
    
    print("\n[2/3] Generating client keys...")
    client_ids = list('ABCDEFGHIJ')
    client_keys = generate_client_keys(client_ids)
    
    node_keys_file = 'src/shared/keys/node_keys.json'
    client_keys_file = 'src/shared/keys/client_keys.json'
    bls_keys_file = 'src/shared/keys/bls_keys.json'
    
    print(f"\n[3/3] Saving keys...")
    print(f"  - Node ECDSA keys to {node_keys_file}...")
    with open(node_keys_file, 'w') as f:
        json.dump(node_keys, f, indent=4)
    
    print(f"  - Client keys to {client_keys_file}...")
    with open(client_keys_file, 'w') as f:
        json.dump(client_keys, f, indent=4)
    
    print(f"  - Node BLS keys to {bls_keys_file}...")
    with open(bls_keys_file, 'w') as f:
        json.dump(bls_keys, f, indent=4)
    

    print("Key generation complete!")
    print("="*60)
    print(f"Generated:")
    print(f"  - {len(node_keys)} node ECDSA key pairs (n1-n7)")
    print(f"  - {len(bls_keys)} node BLS key pairs (n1-n7)")
    print(f"  - {len(client_keys)} client ECDSA key pairs (A-J)")
    print(f"Keys saved to:")
    print(f"  - {node_keys_file}")
    print(f"  - {bls_keys_file}")
    print(f"  - {client_keys_file}")
    print("="*60)

if __name__ == '__main__':
    main()
