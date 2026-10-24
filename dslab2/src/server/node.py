import hashlib
import json
import base64
import threading
import time
import os
import grpc
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


from google.protobuf.empty_pb2 import Empty
from protos import pbft_pb2 as pbft
from protos import pbft_pb2_grpc
from protos import client_pb2_grpc

from shared.config import *
from shared.logger import setup_logger, clear_log
from shared.threshold_sig import (
    ThresholdSignature,
    create_threshold_signature_from_commits,
    create_threshold_signature_from_prepares,
)

KEYS_DIR = os.path.join(os.path.dirname(__file__), '..', 'shared', 'keys')

def load_private(node_id):
    with open(os.path.join(KEYS_DIR, 'node_keys.json'), 'r') as f:
        keys = json.load(f)
    priv_pem = base64.b64decode(keys[node_id]['private'])
    return serialization.load_pem_private_key(priv_pem, password=None)

def load_public(node_id):
    with open(os.path.join(KEYS_DIR, 'node_keys.json'), 'r') as f:
        keys = json.load(f)
    pub_pem = base64.b64decode(keys[node_id]['public'])
    return serialization.load_pem_public_key(pub_pem)

def load_all_public():
    with open(os.path.join(KEYS_DIR, 'node_keys.json'), 'r') as f:
        node_keys = json.load(f)
    with open(os.path.join(KEYS_DIR, 'client_keys.json'), 'r') as f:
        client_keys = json.load(f)
    all_public = {}
    for id, k in node_keys.items():
        all_public[id] = serialization.load_pem_public_key(base64.b64decode(k['public']))
    for id, k in client_keys.items():
        all_public[id] = serialization.load_pem_public_key(base64.b64decode(k['public']))
    return all_public

def load_bls_keys():
    try:
        with open(os.path.join(KEYS_DIR, 'bls_keys.json'), 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return None

def load_bls_public_keys():
    """Load all BLS public keys"""
    bls_keys = load_bls_keys()
    if not bls_keys:
        return {}
    return {node_id: keys['public'] for node_id, keys in bls_keys.items()}

def hash_request(request):
    return hashlib.sha256(request.SerializeToString()).digest()

def sign(message, private_key, signer_id):
    message.signature.CopyFrom(pbft.Signature())
    digest = hashlib.sha256(message.SerializeToString()).digest()
    sig = private_key.sign(digest, ec.ECDSA(hashes.SHA256()))
    return pbft.Signature(signer=signer_id, sig=sig)

def sign_with_bls(message, bls_private_key, signer_id):
    from blspy import PrivateKey, AugSchemeMPL
    
    message.signature.CopyFrom(pbft.Signature())
    digest = hashlib.sha256(message.SerializeToString()).digest()
    
    sk = PrivateKey.from_bytes(bytes.fromhex(bls_private_key))
    bls_sig = AugSchemeMPL.sign(sk, digest)
    
    return pbft.Signature(signer=signer_id, sig=bytes(bls_sig))

class Node:
    def __init__(self, id):
        self.id = id
        self.logger = setup_logger(id)
        self.view = 1
        self.seq = 0
        self.last_executed_seq = 0
        self.datastore = {cid: INITIAL_BALANCE for cid in CLIENT_IDS}
        # SmallBank data structures
        self.smallbank_accounts = {}  # name -> customer_id
        self.smallbank_savings = {}   # customer_id -> balance
        self.smallbank_checking = {}  # customer_id -> balance
        self.executed_requests = set()  # {(client_id, timestamp)} - prevent duplicate execution
        self.log = {}  # seq -> {'request': Request, 'status': pbft.Status.X, 'digest': bytes, 'view': int, 'prepares': {node: Prepare}, 'commits': {node: Commit}}
        self.new_views = [] 
        self.current_leader = get_leader(self.view)
        self.private_key = load_private(id)
        self.public_keys = load_all_public()
        
        self.bls_keys = load_bls_keys()
        self.bls_public_keys = load_bls_public_keys()
        self.bls_private_key = self.bls_keys[id]['private'] if self.bls_keys else None
        
        if USE_THRESHOLD_SIGNATURES:
            self.tss = ThresholdSignature(id, NODE_IDS)
            if self.bls_keys:
                self.logger.info(f"BLS Threshold Signature Scheme enabled for {id}")
            else:
                self.logger.warning(f"TSS enabled but no BLS keys found, falling back to ECDSA aggregation")
        else:
            self.tss = None
        
        self.stubs = {}
        for nid in NODE_IDS:
            if nid != id:
                node_num = int(nid[1:])
                channel = grpc.insecure_channel(NODE_ADDRESSES[node_num])
                self.stubs[nid] = pbft_pb2_grpc.PbftServiceStub(channel)
        channel = grpc.insecure_channel(f'localhost:{CLIENT_PORT}')
        self.client_stub = client_pb2_grpc.ClientServiceStub(channel)
        self.view_change_timers = {}
        self.view_change_timer = None
        self.view_changes = {}
        self.in_view_change = False
        self.target_view = None
        
        # Checkpointing data structures
        if USE_CHECKPOINTING:
            self.checkpoint_messages = {}  # seq -> {node_id -> Checkpoint}
            self.stable_checkpoint = None  # Latest CheckpointCertificate with 2F+1 signatures
            self.last_checkpoint_seq = 0 
            self.logger.info(f"Checkpointing enabled with interval {CHECKPOINT_INTERVAL}")
        else:
            self.checkpoint_messages = {}
            self.stable_checkpoint = None
            self.last_checkpoint_seq = 0
        self.live = True
        self.byzantine = False
        self.attack = ''
        self.dark_targets = []
        self.equivocation_targets = [] 
        self.lock = threading.Lock()

    def reset(self):
        self.view = 1
        self.seq = 0
        self.last_executed_seq = 0
        self.datastore = {cid: INITIAL_BALANCE for cid in CLIENT_IDS}
        # Reset SmallBank data
        self.smallbank_accounts = {}
        self.smallbank_savings = {}
        self.smallbank_checking = {}
        self.executed_requests = set()
        self.log = {}
        self.new_views = []
        self.current_leader = get_leader(self.view)
        self.view_changes = {}
        self.in_view_change = False
        self.target_view = None

        for timer in self.view_change_timers.values():
            if timer and timer.is_alive():
                timer.cancel()
        self.view_change_timers = {}
        
        if USE_CHECKPOINTING:
            self.checkpoint_messages = {}
            self.stable_checkpoint = None
            self.last_checkpoint_seq = 0
        
        self.live = True
        self.byzantine = False
        self.attack = ''
        self.dark_targets = []
        self.equivocation_targets = []
        if self.view_change_timer:
            self.view_change_timer.cancel()
        self.view_change_timer = None
        clear_log(self.logger)
        self.logger.info(f"Node {self.id} reset complete")

    def set_mode(self, live, byzantine, attack):
        with self.lock:
            self.live = live
            self.byzantine = byzantine
            self.attack = attack
            self.dark_targets = []
            self.equivocation_targets = []
            
            if 'dark' in attack:
                # parse dark(n2,n3) or dark(n2, n3) -> ['n2','n3']
                dark_start = attack.find('dark(')
                if dark_start != -1:
                    start = dark_start + 5  # length of 'dark('
                    end = attack.find(')', start)
                    if end != -1:
                        self.dark_targets = [n.strip() for n in attack[start:end].split(',')]
            
            if 'equivocation' in attack:
                # parse equivocation(n2,n3) or equivocation(n2, n3) -> ['n2','n3']
                equiv_start = attack.find('equivocation(')
                if equiv_start != -1:
                    start = equiv_start + 13  # length of 'equivocation('
                    end = attack.find(')', start)
                    if end != -1:
                        self.equivocation_targets = [n.strip() for n in attack[start:end].split(',')]
            
            self.logger.info(f'Set mode: live={live}, byz={byzantine}, attack={attack}, dark_targets={self.dark_targets}, equiv_targets={self.equivocation_targets}')

    def is_leader(self):
        return self.id == self.current_leader

    def get_leader(self, view):
        return get_leader(view)

    def validate_signature(self, message, public_key):
        sig = message.signature.sig
        signer = message.signature.signer
        msg_copy = type(message)()
        msg_copy.CopyFrom(message)
        msg_copy.signature.Clear()
        digest = hashlib.sha256(msg_copy.SerializeToString()).digest()
        try:
            public_key.verify(sig, digest, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

    def validate_aggregated_signature(self, message, public_key):
        sig = message.collector_signature.sig
        signer = message.collector_signature.signer
        msg_copy = type(message)()
        msg_copy.CopyFrom(message)
        msg_copy.collector_signature.Clear()
        digest = hashlib.sha256(msg_copy.SerializeToString()).digest()
        try:
            public_key.verify(sig, digest, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

    def sign_message(self, message):
        message.signature.CopyFrom(sign(message, self.private_key, self.id))
    
    def sign_message_bls(self, message):
        if self.bls_private_key:
            message.signature.CopyFrom(sign_with_bls(message, self.bls_private_key, self.id))
        else:
            self.sign_message(message)

    def sign_aggregated_message(self, message):
        message.collector_signature.CopyFrom(pbft.Signature())  # clear for hash
        digest = hashlib.sha256(message.SerializeToString()).digest()
        sig = self.private_key.sign(digest, ec.ECDSA(hashes.SHA256()))
        message.collector_signature.CopyFrom(pbft.Signature(signer=self.id, sig=sig))

    def broadcast(self, method, message, exclude=[]):
        if not self.live:
            self.logger.debug(f"Broadcast blocked: node not live")
            return
        
        if self.byzantine and 'crash' in self.attack:
            if self.is_leader():
                if method in ['SendAggregatedPrepare', 'SendAggregatedCommit', 'SendNewView']:
                    self.logger.warning(f"Crash attack (Leader): blocking {method}")
                    return
            else:
                if method == 'SendViewChange':
                    pass
                else:
                    self.logger.warning(f"Crash attack (Backup): blocking broadcast {method}")
                    return
        
        if self.byzantine and 'time' in self.attack and self.is_leader():
            self.logger.debug(f"Timing attack: delaying before {method} by {TA_DELAY}s")
            time.sleep(TA_DELAY)
        
        sent_count = 0
        for nid in NODE_IDS:
            if nid != self.id and nid not in exclude:
                if self.byzantine and 'dark' in self.attack and nid in self.dark_targets:
                    self.logger.debug(f"Dark attack: skipping {nid}")
                    continue
                
                try:
                    if method == 'SendPrePrepare':
                        self.stubs[nid].SendPrePrepare(message, timeout=1.5)
                    elif method == 'SendAggregatedPrepare':
                        self.stubs[nid].SendAggregatedPrepare(message, timeout=1.5)
                    elif method == 'SendAggregatedCommit':
                        self.stubs[nid].SendAggregatedCommit(message, timeout=1.5)
                    elif method == 'SendViewChange':
                        self.stubs[nid].SendViewChange(message, timeout=1.5)
                    elif method == 'SendNewView':
                        self.stubs[nid].SendNewView(message, timeout=1.5)
                    else:
                        self.logger.error(f"Unknown method: {method}")
                        continue
                    sent_count += 1
                except Exception as e:
                    self.logger.error(f"Failed to send {method} to {nid}: {e}")
        self.logger.debug(f"Broadcast {method} to {sent_count} nodes")
    
    def collect_prepares(self, pre_prepare):
        prepare_responses = []
        
        self.logger.info(f"[LEADER] Collecting Prepare responses for seq={pre_prepare.seq}")
        
        if self.byzantine and 'time' in self.attack:
            self.logger.debug(f"Timing attack: delaying before sending PrePrepares by {TA_DELAY}s")
            time.sleep(TA_DELAY)
        
        for nid in NODE_IDS:
            if nid == self.id:
                continue
            
            if self.byzantine and 'dark' in self.attack and nid in self.dark_targets:
                self.logger.debug(f"Dark attack: not sending PrePrepare to {nid}")
                continue
            
            message_to_send = pre_prepare
            if self.byzantine and 'equivocation' in self.attack and nid in self.equivocation_targets:
                # Assign NEXT sequence number (seq+1) to the SAME request
                equivocal_seq = pre_prepare.seq + 1
                digest = hash_request(pre_prepare.request)
                message_to_send = pbft.PrePrepare(
                    view=pre_prepare.view,
                    seq=equivocal_seq,
                    digest=digest,
                    request=pre_prepare.request
                )
                self.sign_message(message_to_send)
                self.logger.warning(f"Equivocation: sending PrePrepare with seq={equivocal_seq} (instead of {pre_prepare.seq}) to {nid}")
            
            try:
                prepare = self.stubs[nid].SendPrePrepare(message_to_send, timeout=1.5)
                if prepare and prepare.node_id:
                    if USE_THRESHOLD_SIGNATURES and self.bls_private_key:
                        # Validate BLS signature
                        from blspy import G1Element, G2Element, AugSchemeMPL
                        try:
                            prepare_copy = pbft.Prepare()
                            prepare_copy.CopyFrom(prepare)
                            prepare_copy.signature.Clear()
                            digest_to_verify = hashlib.sha256(prepare_copy.SerializeToString()).digest()
                            
                            pk_hex = self.bls_public_keys.get(prepare.node_id)
                            if pk_hex:
                                pk = G1Element.from_bytes(bytes.fromhex(pk_hex))
                                bls_sig = G2Element.from_bytes(prepare.signature.sig)
                                
                                if AugSchemeMPL.verify(pk, digest_to_verify, bls_sig):
                                    prepare_responses.append(prepare)
                                    self.logger.info(f"[LEADER] Received Prepare from {nid} (BLS)")
                                else:
                                    self.logger.warning(f"[LEADER] Invalid BLS Prepare signature from {nid}")
                            else:
                                self.logger.warning(f"[LEADER] No BLS public key for {nid}")
                        except Exception as e:
                            self.logger.warning(f"[LEADER] BLS signature validation error from {nid}: {e}")
                    elif self.validate_signature(prepare, self.public_keys[prepare.node_id]):
                        prepare_responses.append(prepare)
                        self.logger.info(f"[LEADER] Received valid Prepare from {nid}")
                    else:
                        self.logger.warning(f"[LEADER] Invalid Prepare signature from {nid}")
                else:
                    # self.logger.debug(f"[LEADER] Empty Prepare response (node might be crahsed or not live) from {nid}")
                    pass
            except Exception as e:
                self.logger.error(f"[LEADER] Failed to get Prepare from {nid}: {e}")
        
        self.logger.info(f"[LEADER] Collected {len(prepare_responses)}/{len(NODE_IDS)-1} Prepare responses excluding self")
        return prepare_responses
    
    def send_aggregated_commit_directly(self, seq, digest, prepare_responses):
        self.logger.info(f"[LEADER] Performing Optimistic phase reduction - we have 3F+1 Prepares")
    
        commit_responses = []
        
        leader_commit = pbft.Commit(view=self.view, seq=seq, digest=digest, node_id=self.id)
        
        if self.byzantine and 'sign' in self.attack:
            leader_commit.signature.CopyFrom(pbft.Signature(signer=self.id, sig=b'bad_signature'))
            self.logger.warning("Signature attack: Byzantine leader sending invalid Commit signature")
        elif USE_THRESHOLD_SIGNATURES and self.bls_private_key:
            self.sign_message_bls(leader_commit)
        else:
            self.sign_message(leader_commit)
            
        commit_responses.append(leader_commit)
        
        for prep in prepare_responses:
            if prep.node_id != self.id: 
                commit = pbft.Commit(view=prep.view, seq=prep.seq, digest=prep.digest, node_id=prep.node_id)
                commit.signature.CopyFrom(prep.signature)  # Reuse the signature from Prepare
                commit_responses.append(commit)

        with self.lock:
            for comm in commit_responses:
                self.log[seq]['commits'][comm.node_id] = comm
            self.log[seq]['status'] = pbft.Status.C
        
        self.logger.info(f"[LEADER] Optimistic phase reduction - Creating AggregatedCommit for seq {seq}")
        
        if USE_THRESHOLD_SIGNATURES and self.tss:
            
            commits_dict = {c.node_id: c for c in commit_responses}
            threshold_sig, signer_ids = create_threshold_signature_from_commits(self.tss, commits_dict)
            
            agg_commit = pbft.AggregatedCommit(
                view=self.view,
                seq=seq,
                digest=digest,
                signatures=[],
                use_threshold=True,
                threshold_signature=threshold_sig,
                signer_ids=signer_ids
            )
        else:
            commit_signatures = [c.signature for c in commit_responses]
            agg_commit = pbft.AggregatedCommit(
                view=self.view,
                seq=seq,
                digest=digest,
                signatures=commit_signatures,
                use_threshold=False
            )
        
        self.sign_aggregated_message(agg_commit)
        
        self.broadcast('SendAggregatedCommit', agg_commit)
        self.logger.info(f"[LEADER] Optimistic phase reduction - Calling handle_aggregated_commit for seq {seq}")
        self.handle_aggregated_commit(agg_commit)
        self.logger.info(f"[LEADER] Optimistic phase reduction - handle_aggregated_commit completed for seq {seq}")
    
    def proceed_to_commit_phase(self, seq, digest, prepare_responses):
        use_threshold_prepare = False
        agg = None

        if USE_THRESHOLD_SIGNATURES and self.tss:
            prepare_dict = {p.node_id: p for p in prepare_responses if p and p.node_id}
            if len(prepare_dict) >= TWO_F_PLUS_ONE:
                threshold_sig, signer_ids = create_threshold_signature_from_prepares(self.tss, prepare_dict)
                if threshold_sig and len(signer_ids) >= TWO_F_PLUS_ONE:
                    agg = pbft.AggregatedPrepare(
                        view=self.view,
                        seq=seq,
                        digest=digest,
                        signatures=[],
                        threshold_signature=threshold_sig,
                        signer_ids=signer_ids,
                        use_threshold=True,
                    )
                    use_threshold_prepare = True

        if not use_threshold_prepare:
            signatures = [p.signature for p in prepare_responses]
            agg = pbft.AggregatedPrepare(
                view=self.view,
                seq=seq,
                digest=digest,
                signatures=signatures,
                use_threshold=False,
            )

        self.sign_aggregated_message(agg)
        
        commit_responses = []
        
        leader_commit = pbft.Commit(view=self.view, seq=seq, digest=digest, node_id=self.id)
        
        if self.byzantine and 'sign' in self.attack:
            leader_commit.signature.CopyFrom(pbft.Signature(signer=self.id, sig=b'bad_signature'))
            self.logger.warning("Signature attack: Byzantine leader sending invalid Commit signature")
        elif USE_THRESHOLD_SIGNATURES and self.bls_private_key:
            self.sign_message_bls(leader_commit)
        else:
            self.sign_message(leader_commit)
            
        commit_responses.append(leader_commit)
        
        commit_responses.extend(self.collect_commits(agg))
        
        valid_commits = []
        for comm in commit_responses:
            if comm.seq != seq or comm.digest != digest:
                self.logger.warning(f"[LEADER] Ignoring Commit from {comm.node_id}: seq={comm.seq} (expected {seq}), digest mismatch={comm.digest != digest}")
                continue
            
            if USE_THRESHOLD_SIGNATURES and self.bls_private_key:
                valid_commits.append(comm)
            else:
                try:
                    public_key = self.public_keys.get(comm.node_id)
                    if not public_key:
                        self.logger.warning(f"[LEADER] No public key for {comm.node_id}")
                        continue
                    if not self.validate_signature(comm, public_key):
                        self.logger.warning(f"[LEADER] Invalid Commit signature from {comm.node_id}")
                        continue
                except Exception as e:
                    self.logger.warning(f"[LEADER] Signature validation failed for {comm.node_id}: {e}")
                    continue
                
                valid_commits.append(comm)
        
        if len(valid_commits) >= TWO_F_PLUS_ONE:
            self.logger.info(f"[LEADER] Commit quorum reached for seq {seq}: {len(valid_commits)}/{TWO_F_PLUS_ONE}")
            with self.lock:
                for comm in valid_commits:
                    self.log[seq]['commits'][comm.node_id] = comm
                self.log[seq]['status'] = pbft.Status.C
            
            self.logger.info(f"[LEADER] Creating AggregatedCommit for seq {seq}")
            
            if USE_THRESHOLD_SIGNATURES and self.tss:
                self.logger.info(f"[LEADER] Using Threshold Signature Scheme for seq {seq}")
                
                commits_dict = {c.node_id: c for c in valid_commits}
                threshold_sig, signer_ids = create_threshold_signature_from_commits(self.tss, commits_dict)
                
                agg_commit = pbft.AggregatedCommit(
                    view=self.view,
                    seq=seq,
                    digest=digest,
                    signatures=[],
                    use_threshold=True,
                    threshold_signature=threshold_sig,
                    signer_ids=signer_ids
                )
                self.logger.info(f"[LEADER] Created threshold signature from {len(signer_ids)} nodes")
            else:
                commit_signatures = [c.signature for c in valid_commits]
                agg_commit = pbft.AggregatedCommit(
                    view=self.view,
                    seq=seq,
                    digest=digest,
                    signatures=commit_signatures,
                    use_threshold=False
                )
            
            self.logger.info(f"[LEADER] Signing AggregatedCommit for seq {seq}")
            self.sign_aggregated_message(agg_commit)
            self.logger.info(f"[LEADER] Broadcasting AggregatedCommit for seq {seq}")
            self.broadcast('SendAggregatedCommit', agg_commit)
            
            self.logger.info(f"[LEADER] Calling handle_aggregated_commit for seq {seq}")
            self.handle_aggregated_commit(agg_commit)
            self.logger.info(f"[LEADER] handle_aggregated_commit completed for seq {seq}")
        else:
            self.logger.warning(f"[LEADER] Commit quorum not reached for seq {seq}: {len(valid_commits)}/{TWO_F_PLUS_ONE} (collected {len(commit_responses)} total responses)")
    
    def collect_commits(self, agg_prepare):
        commit_responses = []
        
        for nid in NODE_IDS:
            if nid == self.id:
                continue
            
            if self.byzantine and 'dark' in self.attack and nid in self.dark_targets:
                self.logger.debug(f"Dark attack: not sending AggregatedPrepare to {nid}")
                continue
            
            try:
                commit = self.stubs[nid].SendAggregatedPrepare(agg_prepare, timeout=1.5)
                if commit and commit.node_id:
                    if USE_THRESHOLD_SIGNATURES and self.bls_private_key:
                        # Validate BLS signature
                        from blspy import G1Element, G2Element, AugSchemeMPL
                        try:
                            commit_copy = pbft.Commit()
                            commit_copy.CopyFrom(commit)
                            commit_copy.signature.Clear()
                            digest_to_verify = hashlib.sha256(commit_copy.SerializeToString()).digest()
                            
                            pk_hex = self.bls_public_keys.get(commit.node_id)
                            if pk_hex:
                                pk = G1Element.from_bytes(bytes.fromhex(pk_hex))
                                bls_sig = G2Element.from_bytes(commit.signature.sig)
                                
                                if AugSchemeMPL.verify(pk, digest_to_verify, bls_sig):
                                    commit_responses.append(commit)
                                    self.logger.debug(f"Received Commit from {nid} (BLS)")
                                else:
                                    self.logger.warning(f"Invalid BLS Commit signature from {nid}")
                            else:
                                self.logger.warning(f"No BLS public key for {nid}")
                        except Exception as e:
                            self.logger.warning(f"BLS Commit signature validation error from {nid}: {e}")
                    elif self.validate_signature(commit, self.public_keys[commit.node_id]):
                        commit_responses.append(commit)
                        self.logger.debug(f"Received valid Commit from {nid}")
                    else:
                        self.logger.warning(f"Invalid Commit signature from {nid}")
            except Exception as e:
                self.logger.error(f"Failed to get Commit from {nid}: {e}")
        
        return commit_responses

    def handle_request(self, request):
        if not self.live:
            return "REJECTED:Node not live"
        
        self.logger.debug(f"Received request from client {request.sender}: type={request.type}, ts={request.timestamp}")
        digest = hash_request(request)
        
        if not self.validate_signature(request, self.public_keys[request.sender]):
            self.logger.warning('Invalid request signature')
            return "REJECTED:Invalid signature"

        if request.type == pbft.BALANCE:
            if self.byzantine and 'crash' in self.attack:
                return "REJECTED:Byzantine crash"
            balance = self.datastore.get(request.sender, 0)
            self.logger.info(f"BALANCE query from {request.sender}, balance={balance}")
            reply = pbft.Reply(view=self.view, timestamp=request.timestamp, client_id=request.sender, node_id=self.id, result=str(balance))
            self.sign_message(reply)
            self.client_stub.SendReply(reply)
            return "ACCEPTED"
        else:
            if self.is_leader():

                # Check for duplicate request (same digest already in progress in CURRENT view)
                with self.lock:
                    for seq, entry in self.log.items():
                        if (entry['digest'] == digest and 
                            entry['view'] == self.view and 
                            entry['status'] != pbft.Status.E):
                            self.logger.debug(f"Duplicate request (digest match), already at seq={seq} in view={self.view}")
                            return "ACCEPTED"
                
                
                with self.lock:
                    self.seq += 1
                    current_seq = self.seq
                    current_view = self.view
                    self.log[self.seq] = {'request': request, 'status': pbft.Status.PP, 'digest': digest, 'view': self.view, 'prepares': {}, 'commits': {}}
                
                self.logger.info(f"[LEADER] Starting consensus for seq={current_seq}, ts={request.timestamp}")
                
                self.start_view_change_timer(request.timestamp, digest)
                
                pre_prepare = pbft.PrePrepare(view=current_view, seq=current_seq, digest=digest, request=request)
                self.sign_message(pre_prepare)
                
                prepare_responses = []
                
                leader_prepare = pbft.Prepare(view=current_view, seq=current_seq, digest=digest, node_id=self.id)
                
                if self.byzantine and 'sign' in self.attack:
                    leader_prepare.signature.CopyFrom(pbft.Signature(signer=self.id, sig=b'bad_signature'))
                    self.logger.warning("Signature attack: Byzantine leader sending invalid Prepare signature")
                elif USE_THRESHOLD_SIGNATURES and self.bls_private_key:
                    self.sign_message_bls(leader_prepare)
                else:
                    self.sign_message(leader_prepare)
                    
                prepare_responses.append(leader_prepare)
                prepare_responses.extend(self.collect_prepares(pre_prepare))
                
                seq_digest_groups = {}
                for prep in prepare_responses:
                    key = (prep.seq, prep.digest.hex())
                    if key not in seq_digest_groups:
                        seq_digest_groups[key] = []
                    seq_digest_groups[key].append(prep)
                
                for (seq, digest_hex), preps in seq_digest_groups.items():
                    node_ids = [p.node_id for p in preps]
                    self.logger.info(f"[LEADER] Prepare group: seq={seq}, digest={digest_hex[:8]}..., count={len(preps)}, nodes={node_ids}")
                
                if seq_digest_groups:
                    max_group_key = max(seq_digest_groups, key=lambda k: len(seq_digest_groups[k]))
                    valid_prepares = seq_digest_groups[max_group_key]
                    consensus_seq = max_group_key[0]
                    consensus_digest = bytes.fromhex(max_group_key[1])
                    
                    self.logger.info(f"[LEADER] Largest Prepare group: seq={consensus_seq}, count={len(valid_prepares)}/{TWO_F_PLUS_ONE}")
                else:
                    valid_prepares = []
                    consensus_seq = current_seq
                    consensus_digest = digest
                
                if len(valid_prepares) >= TWO_F_PLUS_ONE:
                    self.logger.info(f"[LEADER] Prepare quorum reached for seq {consensus_seq}: {len(valid_prepares)}/{TWO_F_PLUS_ONE}")
                    
                    if self.byzantine and 'crash' in self.attack:
                        self.logger.warning(f"Crash attack (Leader): received {len(valid_prepares)} Prepares but not proceeding further")
                        with self.lock:
                            if consensus_seq not in self.log:
                                self.log[consensus_seq] = {
                                    'request': request,
                                    'status': pbft.Status.PP,
                                    'digest': consensus_digest,
                                    'view': current_view,
                                    'prepares': {},
                                    'commits': {}
                                }
                            for prep in valid_prepares:
                                self.log[consensus_seq]['prepares'][prep.node_id] = prep
                        return "ACCEPTED"
                    
                    with self.lock:
                        if consensus_seq != current_seq:
                            if current_seq in self.log:
                                del self.log[current_seq]
                            self.seq = consensus_seq
                        
                        if consensus_seq not in self.log:
                            self.log[consensus_seq] = {
                                'request': request,
                                'status': pbft.Status.PP,
                                'digest': consensus_digest,
                                'view': current_view,
                                'prepares': {},
                                'commits': {}
                            }
                        for prep in valid_prepares:
                            self.log[consensus_seq]['prepares'][prep.node_id] = prep
                        
                        if len(valid_prepares) >= TWO_F_PLUS_ONE:
                            self.log[consensus_seq]['status'] = pbft.Status.P
                    
                    if len(valid_prepares) >= THREE_F_PLUS_ONE:
                        self.logger.info(f"[LEADER] Unanimous Prepares ({len(valid_prepares)}/{THREE_F_PLUS_ONE}) - skipping to Commit phase")
                        self.send_aggregated_commit_directly(consensus_seq, consensus_digest, valid_prepares)
                    elif len(valid_prepares) >= TWO_F_PLUS_ONE:
                        self.proceed_to_commit_phase(consensus_seq, consensus_digest, valid_prepares)
                    else:
                        self.logger.warning(f"[LEADER] Not enough valid prepares: {len(valid_prepares)}/{TWO_F_PLUS_ONE}, staying at PP")

                else:
                    self.logger.warning(f"[LEADER] Prepare quorum not reached: largest group has {len(valid_prepares)}/{TWO_F_PLUS_ONE} (collected {len(prepare_responses)} total responses)")
                   
            else:

                self.logger.info(f"[NON-LEADER] Forwarding request to leader {self.current_leader}")
                try:
                    self.stubs[self.current_leader].SendRequest(request, timeout=1.5)
                except Exception as e:
                    self.logger.warning(f"[NON-LEADER] Failed to forward to leader {self.current_leader}: {e}")
        
        return "ACCEPTED"

    def handle_pre_prepare(self, pre_prepare):

        if not self.live:
            self.logger.debug("PrePrepare rejected: node not live")
            return None

        self.logger.info(f"Received PrePrepare from leader: seq={pre_prepare.seq}, view={pre_prepare.view}")
        if self.byzantine and 'dark' in self.attack:
            sender = pre_prepare.signature.signer
            if sender in self.dark_targets:
                self.logger.debug(f"Dark attack: not responding to PrePrepare from {sender}")
                return None
        
        if not self.validate_signature(pre_prepare, self.public_keys[pre_prepare.signature.signer]):
            self.logger.warning(f"PrePrepare signature validation failed from {pre_prepare.signature.signer}")
            return None
        
        if pre_prepare.view != self.view:
            self.logger.debug(f"PrePrepare rejected: wrong view {pre_prepare.view} != {self.view}")
            return None
        
        digest = hash_request(pre_prepare.request)
        if digest != pre_prepare.digest:
            self.logger.warning("PrePrepare rejected: digest mismatch")
            return None
        
        with self.lock:
            if pre_prepare.seq in self.log:
                existing_status = self.log[pre_prepare.seq]['status']
                existing_view = self.log[pre_prepare.seq]['view']
                
                if existing_view == pre_prepare.view:
                    self.logger.debug(f"PrePrepare rejected: seq {pre_prepare.seq} already in log for view {pre_prepare.view}")
                    return None
                
                self.logger.info(f"Re-processing seq {pre_prepare.seq} in new view {pre_prepare.view} (was in view {existing_view}, status={existing_status})")
                
                self.log[pre_prepare.seq]['view'] = pre_prepare.view
                self.log[pre_prepare.seq]['request'] = pre_prepare.request
                self.log[pre_prepare.seq]['digest'] = digest
                
                if existing_status < pbft.Status.PP:
                    self.log[pre_prepare.seq]['status'] = pbft.Status.PP
                    self.logger.info(f"Updated seq {pre_prepare.seq} status: {existing_status} -> PP")
                else:
                    self.logger.info(f"Keeping existing status {existing_status} (not regressing to PP)")
            else:
                self.log[pre_prepare.seq] = {
                    'request': pre_prepare.request,
                    'status': pbft.Status.PP,
                    'digest': digest,
                    'view': pre_prepare.view,
                    'prepares': {},
                    'commits': {}
                }
        
        self.start_view_change_timer(pre_prepare.request.timestamp, digest)
        
        if self.byzantine and 'crash' in self.attack:
            self.logger.warning("Crash attack (Backup): not sending Prepare")
            return None
        
        prepare = pbft.Prepare(view=self.view, seq=pre_prepare.seq, digest=digest, node_id=self.id)
        
        if self.byzantine and 'sign' in self.attack:
            prepare.signature.CopyFrom(pbft.Signature(signer=self.id, sig=b'bad_signature'))
            self.logger.warning("Signature attack: sending invalid Prepare signature")
        else:
            if USE_THRESHOLD_SIGNATURES and self.bls_private_key:
                self.sign_message_bls(prepare)
            else:
                self.sign_message(prepare)
        
        if self.byzantine and 'time' in self.attack:
            self.logger.debug(f"Timing attack: delaying Prepare response by {TA_DELAY}s")
            time.sleep(TA_DELAY)
        
        return prepare

    def handle_aggregated_prepare(self, agg):

        if not self.live or (self.byzantine and 'crash' in self.attack):
            self.logger.debug("AggregatedPrepare rejected: node not live or crashed")
            return None
        self.logger.info(f"Received AggregatedPrepare: seq={agg.seq}")

        if self.byzantine and 'dark' in self.attack:
            sender = agg.collector_signature.signer
            if sender in self.dark_targets:
                self.logger.debug(f"Dark attack: not responding to AggregatedPrepare from {sender}")
                return None
        
        if not self.validate_aggregated_signature(agg, self.public_keys[self.current_leader]):
            self.logger.warning("AggregatedPrepare rejected: invalid leader signature")
            return None
        
        if agg.view != self.view:
            self.logger.debug(f"AggregatedPrepare rejected: wrong view {agg.view} != {self.view}")
            return None
        
        if agg.use_threshold and USE_THRESHOLD_SIGNATURES and self.tss:
            if len(agg.signer_ids) < TWO_F_PLUS_ONE:
                self.logger.warning(f"AggregatedPrepare rejected: not enough signers {len(agg.signer_ids)} < {TWO_F_PLUS_ONE}")
                return None

            message = {
                'view': agg.view,
                'seq': agg.seq,
                'digest': agg.digest.hex()
            }

            keys_to_use = self.bls_public_keys if self.bls_public_keys else self.public_keys

            if not self.tss.verify_threshold_signature(
                message,
                agg.threshold_signature,
                list(agg.signer_ids),
                keys_to_use,
                message_type='prepare'
            ):
                self.logger.warning("AggregatedPrepare rejected: invalid threshold signature")
                return None
        else:
            if len(agg.signatures) < TWO_F_PLUS_ONE:
                self.logger.warning(f"AggregatedPrepare rejected: not enough signatures {len(agg.signatures)} < {TWO_F_PLUS_ONE}")
                return None
            
            valid_count = 0
            for sig in agg.signatures:
                prepare_dummy = pbft.Prepare(view=agg.view, seq=agg.seq, digest=agg.digest, node_id=sig.signer)
                prepare_dummy.signature.CopyFrom(sig)
                if self.validate_signature(prepare_dummy, self.public_keys[sig.signer]):
                    valid_count += 1
                else:
                    self.logger.warning(f"Invalid prepare signature from {sig.signer}, skipping")
            
            if valid_count < TWO_F_PLUS_ONE:
                self.logger.warning(f"AggregatedPrepare rejected: not enough VALID signatures {valid_count} < {TWO_F_PLUS_ONE}")
                return None
        
        with self.lock:
            if agg.seq not in self.log:
                self.logger.warning(f"AggregatedPrepare rejected: seq {agg.seq} not in log")
                return None
            if self.log[agg.seq]['view'] != agg.view or self.log[agg.seq]['digest'] != agg.digest:
                self.logger.warning(f"AggregatedPrepare rejected: view or digest mismatch for seq {agg.seq}")
                return None
            
            # Only update status if going forward (PP -> P, not C -> P or E -> P)
            current_status = self.log[agg.seq]['status']
            if current_status < pbft.Status.P:
                self.log[agg.seq]['status'] = pbft.Status.P
                self.logger.info(f"Updated seq {agg.seq} status: {current_status} -> P")
            else:
                self.logger.info(f"Keeping existing status {current_status} for seq {agg.seq} (not regressing to P)")
        
        if self.byzantine and 'crash' in self.attack:
            self.logger.warning("Crash attack (Backup): not sending Commit")
            return None
        
        commit = pbft.Commit(view=self.view, seq=agg.seq, digest=agg.digest, node_id=self.id)
        
        if self.byzantine and 'sign' in self.attack:
            commit.signature.CopyFrom(pbft.Signature(signer=self.id, sig=b'bad_signature'))
            self.logger.warning("Signature attack: sending invalid Commit signature")
        else:
            if USE_THRESHOLD_SIGNATURES and self.bls_private_key:
                self.sign_message_bls(commit)
            else:
                self.sign_message(commit)
        
        if self.byzantine and 'time' in self.attack:
            self.logger.debug(f"Timing attack: delaying Commit response by {TA_DELAY}s")
            time.sleep(TA_DELAY)
        
        return commit

    def handle_aggregated_commit(self, agg):
        if not self.live or (self.byzantine and 'crash' in self.attack):
            self.logger.debug("AggregatedCommit rejected: node not live or crashed")
            return
        
        if self.byzantine and 'dark' in self.attack:
            sender = agg.collector_signature.signer
            if sender in self.dark_targets:
                self.logger.debug(f"Dark attack: not processing AggregatedCommit from {sender}")
                return
        
        if not self.validate_aggregated_signature(agg, self.public_keys[self.current_leader]):
            self.logger.error("AggregatedCommit rejected: invalid leader signature")
            return
        if agg.view != self.view:
            self.logger.error(f"AggregatedCommit rejected: wrong view {agg.view} != {self.view}")
            return
        
        self.logger.info(f"Received AggregatedCommit: seq={agg.seq}, use_threshold={agg.use_threshold}")
        
        if agg.use_threshold and USE_THRESHOLD_SIGNATURES and self.tss:
            if len(agg.signer_ids) < TWO_F_PLUS_ONE:
                self.logger.error(f"AggregatedCommit rejected: not enough signers {len(agg.signer_ids)} < {TWO_F_PLUS_ONE}")
                return
            
            message = {
                'view': agg.view,
                'seq': agg.seq,
                'digest': agg.digest.hex()
            }
            
            self.logger.debug(f"TSS Verify: seq={agg.seq}, signer_ids={list(agg.signer_ids)}, sig_len={len(agg.threshold_signature)}")
            
            keys_to_use = self.bls_public_keys if self.bls_public_keys else self.public_keys
            
            if not self.tss.verify_threshold_signature(
                message,
                agg.threshold_signature,
                list(agg.signer_ids),
                keys_to_use,
                message_type='commit'
            ):
                self.logger.error(f"AggregatedCommit rejected: invalid threshold signature")
                return
            
            self.logger.info(f"BLS Threshold signature verified for seq={agg.seq} from {len(agg.signer_ids)} signers")
        else:
            if len(agg.signatures) < TWO_F_PLUS_ONE:
                self.logger.error(f"AggregatedCommit rejected: not enough signatures {len(agg.signatures)} < {TWO_F_PLUS_ONE}")
                return
            
            # Validate individual signatures and filter out invalid ones
            valid_count = 0
            for sig in agg.signatures:
                commit_dummy = pbft.Commit(view=agg.view, seq=agg.seq, digest=agg.digest, node_id=sig.signer)
                commit_dummy.signature.CopyFrom(sig)
                if self.validate_signature(commit_dummy, self.public_keys[sig.signer]):
                    valid_count += 1
                else:
                    self.logger.error(f"Invalid commit signature from {sig.signer}, skipping")
            
            # Check if we have enough VALID signatures
            if valid_count < TWO_F_PLUS_ONE:
                self.logger.error(f"AggregatedCommit rejected: not enough VALID signatures {valid_count} < {TWO_F_PLUS_ONE}")
                return
        
        with self.lock:
            if agg.seq not in self.log:
                return
            if self.log[agg.seq]['view'] != agg.view or self.log[agg.seq]['digest'] != agg.digest:
                return
            
            current_status = self.log[agg.seq]['status']
            if current_status < pbft.Status.C:
                self.log[agg.seq]['status'] = pbft.Status.C
                self.logger.info(f"Updated seq {agg.seq} status: {current_status} -> C")
            else:
                self.logger.info(f"Keeping existing status {current_status} for seq {agg.seq} (not regressing to C)")
        
        self.execute(agg.seq)
        
        self.execute_pending_sequences(agg.seq + 1)
        
        with self.lock:
            if agg.seq in self.log and 'request' in self.log[agg.seq]:
                request_timestamp = self.log[agg.seq]['request'].timestamp
                self.cancel_view_change_timer(request_timestamp, agg.digest)
        
        self.logger.debug(f"AggregatedCommit finished for seq={agg.seq}")

    def execute_pending_sequences(self, start_seq):
        seq = start_seq
        while seq in self.log and self.log[seq]['status'] == pbft.Status.C:
            self.execute(seq)
            seq += 1

    def execute(self, seq):
        if not self.live or (self.byzantine and 'crash' in self.attack):
            return
        
        with self.lock:
            if seq != self.last_executed_seq + 1:
                self.logger.debug(f"Cannot execute seq={seq} yet: last_executed_seq={self.last_executed_seq}, expected {self.last_executed_seq + 1}")
                return
            
            entry = self.log[seq]
            request = entry['request']
            
            if request.sender == "NO-OP" and request.receiver == "NO-OP":
                self.logger.info(f"Executing NO-OP for seq={seq}")
                entry['status'] = pbft.Status.E
                self.last_executed_seq = seq
                return
            
            request_key = (request.sender, request.timestamp)
            if request_key in self.executed_requests:
                entry['status'] = pbft.Status.E
                self.last_executed_seq = seq
                return
            
            self.executed_requests.add(request_key)
            
            if ':' in request.receiver and request.receiver.split(':')[0] in ['INIT', 'BAL', 'DC', 'TS', 'WC', 'AMG']:
                result = self.execute_smallbank_operation(request.receiver)
            else:
                result = "failed: insufficient balance"
                if self.datastore[request.sender] >= request.amount:
                    self.datastore[request.sender] -= request.amount
                    self.datastore[request.receiver] += request.amount
                    result = "success"
            
            entry['status'] = pbft.Status.E
            self.last_executed_seq = seq
            self.logger.info(f"Executed seq={seq}, result={result}, sending reply to client")
            reply = pbft.Reply(view=self.view, timestamp=request.timestamp, client_id=request.sender, node_id=self.id, result=result)
            self.sign_message(reply)
            
        self.check_and_create_checkpoint(seq)
        
        try:
            self.client_stub.SendReply(reply, timeout=1.5)
        except Exception as e:
            self.logger.error(f"Failed to send reply to client: {e}")

    def start_view_change_timer(self, timestamp, digest):
        request_key = (timestamp, digest.hex() if isinstance(digest, bytes) else digest)
        
        if request_key in self.view_change_timers:
            timer = self.view_change_timers[request_key]
            if timer and timer.is_alive():
                self.logger.debug(f"View change timer already running for request ts={timestamp}, not restarting")
                return
        
        timer = threading.Timer(VIEW_CHANGE_TIMEOUT, lambda: self.trigger_view_change(request_key))
        timer.start()
        self.view_change_timers[request_key] = timer
        self.logger.debug(f"Started view change timer for request ts={timestamp} ({VIEW_CHANGE_TIMEOUT}s)")
    
    def cancel_view_change_timer(self, timestamp, digest):
        request_key = (timestamp, digest.hex() if isinstance(digest, bytes) else digest)
        
        if request_key in self.view_change_timers:
            timer = self.view_change_timers[request_key]
            if timer and timer.is_alive():
                timer.cancel()
            del self.view_change_timers[request_key]
            self.logger.debug(f"Cancelled view change timer for request ts={timestamp}")

    def trigger_view_change(self, request_key=None):
        
        if request_key and request_key in self.view_change_timers:
            del self.view_change_timers[request_key]
        
        with self.lock:
            if request_key is not None:
                if self.in_view_change:
                    self.logger.debug(f"Per-request timer expired but already in view change, ignoring")
                    return
                target_view = self.view + 1
                self.logger.warning(f"VIEW CHANGE TIMER EXPIRED - Initiating view change from view {self.view} to {target_view}")
            else:
                if not self.in_view_change:
                    self.logger.warning("NewView timeout fired but not in view change - ignoring")
                    return
                base_view = self.target_view if self.target_view else self.view
                target_view = base_view + 1
                self.logger.warning(f"NewView TIMEOUT - Leader for view {base_view} unresponsive, skipping to view {target_view}")
                self.in_view_change = False
            
            if self.view_change_timer:
                self.view_change_timer.cancel()
                self.view_change_timer = None
            
            self.in_view_change = True
            self.target_view = target_view
            
            new_view = target_view
            prepared = []
            
            if USE_CHECKPOINTING and self.stable_checkpoint:
                n = self.stable_checkpoint.sequence_number
            else:
                n = 0
            
            for seq, entry in self.log.items():
                if seq > n and entry['status'] in {pbft.Status.P, pbft.Status.C, pbft.Status.E}:
                    prepared.append(pbft.PreparedRequest(seq=seq, digest=entry['digest'], view=entry['view']))
                    self.logger.info(f"Including seq={seq} (status={entry['status']}) in ViewChange prepared set")
            
            self.logger.info(f'Broadcasting ViewChange: new_view={new_view}, n={n}, prepared_count={len(prepared)}')
            vc = pbft.ViewChange(new_view=new_view, last_seq=n, prepared=prepared, node_id=self.id)
            
            if USE_CHECKPOINTING and self.stable_checkpoint:
                vc.stable_checkpoint.CopyFrom(self.stable_checkpoint)
                self.logger.info(f"Including stable checkpoint seq={self.stable_checkpoint.sequence_number} in ViewChange")
            
            if self.byzantine and 'sign' in self.attack:
                vc.signature.CopyFrom(pbft.Signature(signer=self.id, sig=b'bad_signature'))
                self.logger.warning("Signature attack: sending invalid ViewChange signature")
            else:
                self.sign_message(vc)
            
            if new_view not in self.view_changes:
                self.view_changes[new_view] = []
            self.view_changes[new_view].append(vc)
            self.logger.debug(f"Stored own ViewChange for view {new_view}")
        
        self.broadcast('SendViewChange', vc)
        
        with self.lock:
            if not self.in_view_change:
                self.logger.debug("ViewChange completed while broadcasting, not starting timeout timer")
                return
            
            self.view_change_timer = threading.Timer(VIEW_CHANGE_TIMEOUT * 2, self.trigger_view_change)
            self.view_change_timer.start()
            self.logger.debug(f"Started view change TIMEOUT timer ({VIEW_CHANGE_TIMEOUT * 2}s) - will trigger next view change if NewView not received")

    def handle_view_change(self, vc):
        if not self.live:
            return
        if not self.validate_signature(vc, self.public_keys[vc.node_id]):
            self.logger.warning(f"Invalid ViewChange signature from {vc.node_id}")
            return
        new_view = vc.new_view
        self.logger.info(f"Received ViewChange from {vc.node_id} for view {new_view}, prepared_count={len(vc.prepared)}")
        
        should_create_new_view = False
        view_changes_snapshot = None
        log_snapshot = None
        
        with self.lock:
            if new_view <= self.view:
                self.logger.debug(f"Ignoring ViewChange for old view {new_view} (current view: {self.view})")
                return
            
            if new_view not in self.view_changes:
                self.view_changes[new_view] = []
            self.view_changes[new_view].append(vc)
            
            current_count = len(self.view_changes[new_view])
            self.logger.info(f"ViewChange count for view {new_view}: {current_count}/{TWO_F_PLUS_ONE}")
            
            if current_count == TWO_F_PLUS_ONE and self.id == get_leader(new_view):
                should_create_new_view = True
                view_changes_snapshot = list(self.view_changes[new_view])
                log_snapshot = dict(self.log) 
                del self.view_changes[new_view]
        
        if should_create_new_view:
            self.logger.warning(f"I AM THE NEW LEADER for view = {new_view} - Creating NewView message...")
            
            with self.lock:
                if self.view_change_timer:
                    self.view_change_timer.cancel()
                    self.view_change_timer = None
                self.view = new_view
                self.current_leader = get_leader(self.view)
                self.in_view_change = False
                self.target_view = None
                self.logger.warning(f"NEW LEADER transitioning to view {new_view}")
            

            pre_prepares = []
            
            min_s = 0
            for vc in view_changes_snapshot:
                if USE_CHECKPOINTING and vc.stable_checkpoint and vc.stable_checkpoint.sequence_number > 0:
                    min_s = max(min_s, vc.stable_checkpoint.sequence_number)
                min_s = max(min_s, vc.last_seq)
            
            self.logger.info(f"Constructing NewView: min_s (highest checkpoint) = {min_s}")
            
            max_s = min_s
            for vc in view_changes_snapshot:
                for p in vc.prepared:
                    max_s = max(max_s, p.seq)
            
            self.logger.info(f"max_s (highest prepared) = {max_s}")
            
            prepared_map = {}  # seq -> list of (digest, view, node_id)
            for vc in view_changes_snapshot:
                for p in vc.prepared:
                    if p.seq not in prepared_map:
                        prepared_map[p.seq] = []
                    prepared_map[p.seq].append((p.digest, p.view, vc.node_id))
            
            for seq in range(min_s + 1, max_s + 1):
                if seq in prepared_map:
                    digest, view, node_id = prepared_map[seq][0]
                    
                    if seq in log_snapshot and log_snapshot[seq]['digest'] == digest:
                        request = log_snapshot[seq]['request']
                        self.logger.info(f"Re-proposing seq={seq} from own log (found {len(prepared_map[seq])} nodes with it)")
                    else:
                        self.logger.warning(f"Seq={seq} prepared by {len(prepared_map[seq])} nodes, but not in leader's log - using NO-OP")
                        request = pbft.Request(
                            type=pbft.TRANSFER,
                            sender="NO-OP",
                            receiver="NO-OP",
                            amount=0,
                            timestamp=seq
                        )
                        digest = hash_request(request)
                    
                    pp = pbft.PrePrepare(view=new_view, seq=seq, digest=digest, request=request)
                    self.sign_message(pp)
                    pre_prepares.append(pp)
                    self.logger.info(f"Including seq={seq} in NewView O")
                else:
                    self.logger.warning(f"No node prepared seq={seq} - creating NO-OP to fill gap")
                    request = pbft.Request(
                        type=pbft.TRANSFER,
                        sender="NO-OP",
                        receiver="NO-OP",
                        amount=0,
                        timestamp=seq
                    )
                    digest = hash_request(request)
                    pp = pbft.PrePrepare(view=new_view, seq=seq, digest=digest, request=request)
                    self.sign_message(pp)
                    pre_prepares.append(pp)
                    self.logger.info(f"Created NO-OP for gap at seq={seq}")
            
            self.logger.info(f"Broadcasting NewView: view={new_view}, re-proposing {len(pre_prepares)} requests")
            nv = pbft.NewView(view=new_view, view_changes=view_changes_snapshot, pre_prepares=pre_prepares)
            
            if self.byzantine and 'sign' in self.attack:
                nv.signature.CopyFrom(pbft.Signature(signer=self.id, sig=b'bad_signature'))
                self.logger.warning("Signature attack: sending invalid NewView signature")
            else:
                self.sign_message(nv)
            

            with self.lock:
                self.new_views.append(nv)
            
            self.broadcast('SendNewView', nv)

    def handle_new_view(self, nv):
        if not self.live:
            return
        
        self.logger.info(f"Received NewView for view {nv.view} from new leader {get_leader(nv.view)}")
        
        if not self.validate_signature(nv, self.public_keys[get_leader(nv.view)]):
            self.logger.error(f"Invalid NewView signature from {get_leader(nv.view)}")
            return
        if nv.view <= self.view:
            self.logger.debug(f"Ignoring NewView for old/current view {nv.view} (current: {self.view})")
            return

        if len(nv.view_changes) < TWO_F_PLUS_ONE:
            self.logger.error(f"NewView rejected: insufficient ViewChanges {len(nv.view_changes)}/{TWO_F_PLUS_ONE}")
            return
        for vc in nv.view_changes:
            if not self.validate_signature(vc, self.public_keys[vc.node_id]):
                self.logger.error(f"Invalid ViewChange signature in NewView from {vc.node_id}")
                return
        
        with self.lock:
            if self.view_change_timer:
                self.view_change_timer.cancel()
                self.view_change_timer = None
            
            old_view = self.view
            old_leader = self.current_leader
            self.view = nv.view
            self.current_leader = get_leader(self.view)
            self.new_views.append(nv)

            self.in_view_change = False
            self.target_view = None
            
            self.logger.info(f"VIEW CHANGED: {old_view} → {nv.view}, Leader: {old_leader} → {self.current_leader}")
            
            min_s = 0
            stable_checkpoint_digest = None
            checkpoint_source_node = None
            for vc in nv.view_changes:
                if USE_CHECKPOINTING and vc.stable_checkpoint and vc.stable_checkpoint.sequence_number > 0:
                    if vc.stable_checkpoint.sequence_number > min_s and vc.node_id != self.id:
                        min_s = vc.stable_checkpoint.sequence_number
                        stable_checkpoint_digest = vc.stable_checkpoint.state_digest
                        checkpoint_source_node = vc.node_id
                min_s = max(min_s, vc.last_seq)
            
            if min_s > 0:
                self.logger.info(f"NewView indicates stable checkpoint at seq={min_s}")
            
            need_catch_up = False
            if min_s > 0 and self.last_executed_seq < min_s:
                self.logger.warning(f"Need to catch up: last_executed={self.last_executed_seq}, stable_checkpoint={min_s}")
                need_catch_up = True
            
            is_new_leader = self.is_leader()
            current_view = self.view
        
        if need_catch_up and stable_checkpoint_digest and checkpoint_source_node:
            self.logger.info(f"Attempting to catch up from {checkpoint_source_node} to seq={min_s}")
            success = self.catch_up_to_checkpoint(min_s, stable_checkpoint_digest, checkpoint_source_node)
            if not success:
                self.logger.error(f"Failed to catch up to checkpoint seq={min_s}, will try to process sequences from NewView")
        
        with self.lock:
            for pp in nv.pre_prepares:
                digest = hash_request(pp.request)
                
                if pp.seq in self.log:
                    existing_status = self.log[pp.seq]['status']
                    self.log[pp.seq]['view'] = nv.view
                    self.logger.info(f"Seq={pp.seq} already in log with status={existing_status}, updated view to {nv.view}")
                else:
                    self.log[pp.seq] = {
                        'request': pp.request,
                        'status': pbft.Status.PP,
                        'digest': digest,
                        'view': nv.view,
                        'prepares': {},
                        'commits': {}
                    }
                    self.logger.info(f"Created new log entry for seq={pp.seq} in view {nv.view}")
            
            is_new_leader = self.is_leader()
            current_view = self.view
            pre_prepares_to_restart = list(nv.pre_prepares) if is_new_leader else []
        
        
        if is_new_leader:
            self.logger.info(f"New leader {self.id} restarting consensus for {len(pre_prepares_to_restart)} requests")
            for pp in pre_prepares_to_restart:
                digest = hash_request(pp.request)
                seq = pp.seq
                request = pp.request
                
                self.start_view_change_timer(request.timestamp, digest)
                
                prepare_responses = []
                
                leader_prepare = pbft.Prepare(view=current_view, seq=seq, digest=digest, node_id=self.id)
                self.sign_message(leader_prepare)
                prepare_responses.append(leader_prepare)
                
                pre_prepare = pbft.PrePrepare(view=current_view, seq=seq, digest=digest, request=request)
                self.sign_message(pre_prepare)
                prepare_responses.extend(self.collect_prepares(pre_prepare))
                
                if len(prepare_responses) >= TWO_F_PLUS_ONE:
                    self.logger.info(f"[viewchange] Prepare quorum reached for seq {seq}: {len(prepare_responses)}/{TWO_F_PLUS_ONE}")
                    with self.lock:
                        for prep in prepare_responses:
                            self.log[seq]['prepares'][prep.node_id] = prep
                        if self.log[seq]['status'] < pbft.Status.P:
                            self.log[seq]['status'] = pbft.Status.P
                    
                    self.proceed_to_commit_phase(seq, digest, prepare_responses)
                else:
                    self.logger.warning(f"[viewchange] Prepare quorum not reached for seq {seq}: {len(prepare_responses)}/{TWO_F_PLUS_ONE}")

    def print_log(self):
        with self.lock:
            output = f"Log for {self.id}:\n"
            for seq, entry in sorted(self.log.items()):
                output += f"Seq {seq}: Status {pbft.Status.Name(entry['status'])}, Request {entry['request']}\n"
            return output

    def print_db(self):
        with self.lock:
            return json.dumps(self.datastore, indent=2)

    def print_status(self, seq):
        with self.lock:
            if seq not in self.log:
                return f"Seq {seq} = X"
            status = pbft.Status.Name(self.log[seq]['status'])
            return f"Seq {seq} = {status}"

    def print_view(self):
        with self.lock:
            output = ""
            for i, nv in enumerate(self.new_views):
                output += f"NewView {i+1}: View {nv.view}, ViewChanges: {len(nv.view_changes)}, PrePrepares: {len(nv.pre_prepares)}\n"
            return output

    # ========== CHECKPOINTING METHODS ==========
    
    def check_and_create_checkpoint(self, seq):
        if not USE_CHECKPOINTING:
            return
            
        if seq > 0 and seq % CHECKPOINT_INTERVAL == 0 and seq > self.last_checkpoint_seq:
            with self.lock:
                state_snapshot = self.datastore.copy()
            
            checkpoint_thread = threading.Thread(
                target=self.create_checkpoint_async, 
                args=(seq, state_snapshot),
                daemon=True
            )
            checkpoint_thread.start()
            self.last_checkpoint_seq = seq
    
    def create_checkpoint_async(self, seq, state_snapshot=None):
        try:
            if state_snapshot is None:
                with self.lock:
                    state_snapshot = self.datastore.copy()
            
            self.logger.debug(f"Creating checkpoint for seq={seq} with provided state snapshot")
                
            state_data = json.dumps(state_snapshot, sort_keys=True)
            state_digest = hashlib.sha256(state_data.encode()).hexdigest()
            
            checkpoint = pbft.Checkpoint(
                sequence_number=seq,
                state_digest=state_digest,
                node_id=self.id
            )
            
            if USE_THRESHOLD_SIGNATURES and self.bls_private_key:
                self.sign_message_bls(checkpoint)
            else:
                self.sign_message(checkpoint)
            
            self.logger.info(f"Created checkpoint at seq={seq}, digest={state_digest[:16]}...")
            
            with self.lock:
                if seq not in self.checkpoint_messages:
                    self.checkpoint_messages[seq] = {}
                self.checkpoint_messages[seq][self.id] = checkpoint
            
            self.broadcast_checkpoint(checkpoint)
            
            self.try_form_checkpoint_certificate(seq)
            
        except Exception as e:
            self.logger.error(f"Failed to create checkpoint at seq={seq}: {e}")
    
    def create_checkpoint(self, seq):
        self.create_checkpoint_async(seq)
    
    def compute_state_digest(self):
        state_data = json.dumps(self.datastore, sort_keys=True)
        digest = hashlib.sha256(state_data.encode()).hexdigest()
        return digest
    
    def broadcast_checkpoint(self, checkpoint):
        for node_id, stub in self.stubs.items():
            try:
                stub.SendCheckpoint(checkpoint, timeout=1.0)
            except Exception as e:
                self.logger.debug(f"Failed to send checkpoint to {node_id}: {e}")
    
    def handle_checkpoint(self, checkpoint):
        if not USE_CHECKPOINTING:
            return
        
        if not self.live:
            self.logger.debug("Checkpoint rejected: node not live")
            return
        
        if self.byzantine and 'crash' in self.attack:
            self.logger.debug("Checkpoint rejected: crash attack")
            return
        
        if self.byzantine and 'dark' in self.attack:
            if checkpoint.node_id in self.dark_targets:
                self.logger.debug(f"Dark attack: not processing checkpoint from {checkpoint.node_id}")
                return
            
        seq = checkpoint.sequence_number
        node_id = checkpoint.node_id
        
        signature_valid = False
        if USE_THRESHOLD_SIGNATURES and self.bls_private_key:
            try:
                from blspy import G1Element, G2Element, AugSchemeMPL
                pk_hex = self.bls_public_keys.get(node_id)
                if pk_hex:
                    public_key = G1Element.from_bytes(bytes.fromhex(pk_hex))
                    msg_copy = type(checkpoint)()
                    msg_copy.CopyFrom(checkpoint)
                    msg_copy.signature.Clear()
                    digest = hashlib.sha256(msg_copy.SerializeToString()).digest()
                    bls_sig = G2Element.from_bytes(checkpoint.signature.sig)
                    signature_valid = AugSchemeMPL.verify(public_key, digest, bls_sig)
                else:
                    self.logger.warning(f"No BLS public key found for {node_id}")
            except Exception as e:
                self.logger.debug(f"BLS signature verification failed for {node_id}: {e}")
        else:
            signature_valid = self.validate_signature(checkpoint, self.public_keys[node_id])
        
        if not signature_valid:
            self.logger.warning(f"Invalid checkpoint signature from {node_id} for seq={seq}")
            return
        
        if seq > self.seq:
            self.logger.warning(f"Received checkpoint for seq={seq} but we're only at seq={self.seq}. Need to catch up!")
            
        if seq not in self.checkpoint_messages:
            self.checkpoint_messages[seq] = {}
        self.checkpoint_messages[seq][node_id] = checkpoint
        
        self.logger.debug(f"Received checkpoint from {node_id} for seq={seq}")
        
        self.try_form_checkpoint_certificate(seq)
    
    def try_form_checkpoint_certificate(self, seq):
        if seq not in self.checkpoint_messages:
            return
            
        checkpoints = self.checkpoint_messages[seq]
        
        digest_groups = {}
        for node_id, checkpoint in checkpoints.items():
            digest = checkpoint.state_digest
            if digest not in digest_groups:
                digest_groups[digest] = []
            digest_groups[digest].append(checkpoint)
        
        for digest, checkpoint_list in digest_groups.items():
            if len(checkpoint_list) >= TWO_F_PLUS_ONE:
                certificate = pbft.CheckpointCertificate(
                    sequence_number=seq,
                    state_digest=digest,
                    checkpoints=checkpoint_list
                )
                
                if seq > self.seq:
                    self.logger.info(f"Need to catch up from seq={self.seq} to seq={seq}")
                    source_node = None
                    for cp in checkpoint_list:
                        if cp.node_id != self.id:
                            source_node = cp.node_id
                            break
                    
                    if source_node is None:
                        self.logger.error(f"No valid source node for catch-up (all checkpoints from self)")
                        return None
                    
                    success = self.catch_up_to_checkpoint(seq, digest, source_node)
                    if not success:
                        self.logger.error(f"Failed to catch up to checkpoint seq={seq}")
                        return None
                elif seq < self.seq:
                    self.logger.debug(f"Received checkpoint for seq={seq}, we're already at seq={self.seq}")
                
                if self.stable_checkpoint is None or seq > self.stable_checkpoint.sequence_number:
                    self.stable_checkpoint = certificate
                    self.logger.info(f"New stable checkpoint formed at seq={seq}, digest={digest[:16]}...")
                
                return certificate
        
        return None
    
    def catch_up_to_checkpoint(self, target_seq, expected_digest, source_node_id):
        try:
            self.logger.info(f"Starting catch-up to seq={target_seq} using source node {source_node_id}")
            
            source_stub = self.stubs.get(source_node_id)
            if not source_stub:
                self.logger.error(f"No stub available for source node {source_node_id}")
                return False
            
            try:
                db_response = source_stub.PrintDB(pbft.Empty(), timeout=2.0)
                checkpoint_state = json.loads(db_response.data)
                self.logger.info(f"Fetched DB state from {source_node_id}: {checkpoint_state}")
            except Exception as e:
                self.logger.error(f"Failed to fetch DB state from {source_node_id}: {e}")
                return False
            
            missing_sequences = list(range(self.seq + 1, target_seq + 1))
            self.logger.info(f"Need to catch up sequences: {missing_sequences}")
            
            for missing_seq in missing_sequences:
                try:
                    status_response = source_stub.PrintStatus(pbft.SeqRequest(seq=missing_seq), timeout=1.0)
                    if "X" in status_response.data:
                        self.logger.warning(f"Sequence {missing_seq} not found on {source_node_id}")
                        continue
                    
                    self.log[missing_seq] = {
                        'status': pbft.Status.E,
                        'request': None,
                        'digest': b'',
                        'view': 1,
                        'prepares': {},
                        'commits': {}
                    }
                    self.logger.info(f"Added log entry for seq={missing_seq}")
                    
                except Exception as e:
                    self.logger.error(f"Failed to fetch log for seq={missing_seq}: {e}")
                    return False
            
            self.seq = target_seq
            self.last_executed_seq = target_seq
            self.datastore = checkpoint_state.copy()
            
            our_digest = self.compute_state_digest()
            if our_digest != expected_digest:
                self.logger.error(f"Catch-up failed: digest mismatch after state update")
                return False
            
            self.logger.info(f"Successfully caught up to seq={target_seq}, state digest matches!")
            return True
            
        except Exception as e:
            self.logger.error(f"Catch-up failed with exception: {e}")
            return False
    
    # ========== SMALLBANK OPERATIONS ==========
    
    def execute_smallbank_operation(self, operation: str) -> str:
        try:
            parts = operation.split(':')
            op_type = parts[0]
            
            if op_type == 'INIT':
                # INIT:name:customer_id:savings_balance:checking_balance
                name, customer_id, savings_bal, checking_bal = parts[1], int(parts[2]), int(parts[3]), int(parts[4])
                self.smallbank_accounts[name] = customer_id
                self.smallbank_savings[customer_id] = savings_bal
                self.smallbank_checking[customer_id] = checking_bal
                return "success"
            
            elif op_type == 'BAL':
                # BAL:name
                name = parts[1]
                if name not in self.smallbank_accounts:
                    return "failed: account not found"
                customer_id = self.smallbank_accounts[name]
                savings = self.smallbank_savings.get(customer_id, 0)
                checking = self.smallbank_checking.get(customer_id, 0)
                total = savings + checking
                return f"success: {total}"
            
            elif op_type == 'DC':
                # DC:name:amount (Deposit Checking)
                name, amount = parts[1], int(parts[2])
                if amount <= 0:
                    return "failed: invalid amount"
                if name not in self.smallbank_accounts:
                    return "failed: account not found"
                customer_id = self.smallbank_accounts[name]
                self.smallbank_checking[customer_id] = self.smallbank_checking.get(customer_id, 0) + amount
                return "success"
            
            elif op_type == 'TS':
                # TS:name:amount (Transact Savings)
                name, amount = parts[1], int(parts[2])
                if name not in self.smallbank_accounts:
                    return "failed: account not found"
                customer_id = self.smallbank_accounts[name]
                current_savings = self.smallbank_savings.get(customer_id, 0)
                new_balance = current_savings + amount
                if new_balance < 0:
                    return "failed: insufficient funds"
                self.smallbank_savings[customer_id] = new_balance
                return "success"
            
            elif op_type == 'WC':
                # WC:name:amount (Write Check)
                name, amount = parts[1], int(parts[2])
                if amount <= 0:
                    return "failed: invalid amount"
                if name not in self.smallbank_accounts:
                    return "failed: account not found"
                customer_id = self.smallbank_accounts[name]
                savings = self.smallbank_savings.get(customer_id, 0)
                checking = self.smallbank_checking.get(customer_id, 0)
                total = savings + checking
                
                if total < amount:
                    # Overdraft with penalty
                    penalty = 1
                    self.smallbank_checking[customer_id] = checking - (amount + penalty)
                else:
                    self.smallbank_checking[customer_id] = checking - amount
                return "success"
            
            elif op_type == 'AMG':
                # AMG:name1:name2 (Amalgamate)
                name1, name2 = parts[1], parts[2]
                if name1 == name2:
                    return "failed: same account"
                if name1 not in self.smallbank_accounts or name2 not in self.smallbank_accounts:
                    return "failed: account not found"
                
                cid1 = self.smallbank_accounts[name1]
                cid2 = self.smallbank_accounts[name2]
                
                # Get balances from name1
                s1 = self.smallbank_savings.get(cid1, 0)
                c1 = self.smallbank_checking.get(cid1, 0)
                total = s1 + c1
                
                # Zero out name1 accounts
                self.smallbank_savings[cid1] = 0
                self.smallbank_checking[cid1] = 0
                
                # Add total to name2's checking
                self.smallbank_checking[cid2] = self.smallbank_checking.get(cid2, 0) + total
                return "success"
            
            else:
                return f"failed: unknown operation {op_type}"
                
        except Exception as e:
            return f"failed: {str(e)}"
