"""
Author: sharshith1312
Name: Harshith Singathala
SBU ID: 116228817
Course: CSE535 - Distributed Systems
BLS Threshold Signature Scheme
Provides true threshold signatures with constant-size aggregated signatures
"""

from blspy import PrivateKey, AugSchemeMPL, G1Element, G2Element
import hashlib
import json

class ThresholdSignature:
    def __init__(self, node_id, node_ids):
        self.node_id = node_id
        self.node_ids = node_ids
        self.n = len(node_ids)

    def sign_message(self, message_bytes, private_key_bytes):
        sk = PrivateKey.from_bytes(bytes.fromhex(private_key_bytes))
        return AugSchemeMPL.sign(sk, message_bytes)

    def verify_threshold_signature(
        self,
        message,
        aggregated_signature,
        signer_ids,
        bls_public_keys=None,
        message_type="commit",
    ):
        try:
            from shared.config import TWO_F_PLUS_ONE
            if len(signer_ids) < TWO_F_PLUS_ONE:
                return False

            if not bls_public_keys or not aggregated_signature:
                return False

            from protos import pbft_pb2 as pbft
            proto_cls = pbft.Commit if message_type == "commit" else pbft.Prepare


            public_keys = []
            messages_to_verify = []
            
            for node_id in signer_ids:
                if node_id not in bls_public_keys:
                    continue
                
                proto_msg = proto_cls(
                    view=message["view"],
                    seq=message["seq"],
                    digest=bytes.fromhex(message["digest"]),
                    node_id=node_id,
                )
                proto_msg.signature.CopyFrom(pbft.Signature())
                msg_bytes = hashlib.sha256(proto_msg.SerializeToString()).digest()
                
                pk_hex = bls_public_keys[node_id]
                pk = G1Element.from_bytes(bytes.fromhex(pk_hex))
                public_keys.append(pk)
                messages_to_verify.append(msg_bytes)
            
            if len(public_keys) < TWO_F_PLUS_ONE:
                return False
            
            agg_sig = G2Element.from_bytes(aggregated_signature)
            
            return AugSchemeMPL.aggregate_verify(public_keys, messages_to_verify, agg_sig)

        except Exception as e:
            print(f"BLS verification error: {e}")
            return False


def _create_threshold_signature_from_messages(messages, bls_private_keys):
    if not messages:
        return None, []

    signatures = []
    signer_ids = []
    failed_signers = []

    for node_id, msg in messages.items():
        if not msg.signature.sig:
            continue
        
        try:
            sig = G2Element.from_bytes(msg.signature.sig)
            signatures.append(sig)
            signer_ids.append(node_id)
        except Exception as e:
            failed_signers.append(node_id)
            continue

    if not signatures:
        return None, []
    
    if failed_signers:
        print(f"Warning: Failed to parse BLS signatures from: {failed_signers}")

    aggregated_sig = AugSchemeMPL.aggregate(signatures)
    
    return bytes(aggregated_sig), signer_ids


def create_threshold_signature_from_commits(tss, commits):
    return _create_threshold_signature_from_messages(commits, {})


def create_threshold_signature_from_prepares(tss, prepares):
    return _create_threshold_signature_from_messages(prepares, {})
