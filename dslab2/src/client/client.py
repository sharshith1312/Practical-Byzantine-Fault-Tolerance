"""
Author: sharshith1312
Name: Harshith Singathala
SBU ID: 116228817
Course: CSE535 - Distributed Systems
"""

import grpc
import time
import subprocess
import sys
import os
import csv
from typing import Any, Dict, List
import json
import base64
import threading
from concurrent.futures import ThreadPoolExecutor
import hashlib
import select
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

from protos import pbft_pb2
from protos import pbft_pb2_grpc
from protos import client_pb2_grpc
from shared import config

KEYS_DIR = os.path.join(os.path.dirname(__file__), '..', 'shared', 'keys')

class Client(pbft_pb2_grpc.PbftServiceServicer):
    def __init__(self, client_id, controller):
        self.client_id = client_id
        self.controller = controller
        self.current_view = 1 
        self.leader = config.get_leader(self.current_view)
        self.timestamp_counter = 0
        self.stubs = {}
        self.pending_replies = {}
        self.pending_quorums = {}
        self.running_benchmark = False
        self.stop_retries = False
        self.lock = threading.Lock()
        self.private_key = self.load_private_key()
        self.public_keys = self.load_public_keys()
        self._update_stubs()

    def load_private_key(self):
        with open(os.path.join(KEYS_DIR, 'client_keys.json'), 'r') as f:
            keys = json.load(f)
        priv_pem = base64.b64decode(keys[self.client_id]['private'])
        return serialization.load_pem_private_key(priv_pem, password=None)

    def load_public_keys(self):
        all_public = {}
        with open(os.path.join(KEYS_DIR, 'node_keys.json'), 'r') as f:
            node_keys = json.load(f)
        with open(os.path.join(KEYS_DIR, 'client_keys.json'), 'r') as f:
            client_keys = json.load(f)
        for id_, k in node_keys.items():
            all_public[id_] = serialization.load_pem_public_key(base64.b64decode(k['public']))
        for id_, k in client_keys.items():
            all_public[id_] = serialization.load_pem_public_key(base64.b64decode(k['public']))
        return all_public

    def _update_stubs(self):
        self.stubs = {}
        for nid in config.NODE_IDS:
            try:
                node_num = int(nid[1:])
                channel = grpc.insecure_channel(config.NODE_ADDRESSES[node_num])
                self.stubs[nid] = pbft_pb2_grpc.PbftServiceStub(channel)
            except Exception as e:
                print(f"Warning: Could not create stub for node {nid}: {e}")

    def sign_message(self, message):
        sig = message.signature
        message.signature.Clear()
        digest = hashlib.sha256(message.SerializeToString()).digest()
        signed = self.private_key.sign(digest, ec.ECDSA(hashes.SHA256()))
        message.signature.sig = signed
        message.signature.signer = self.client_id

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

    def check_enter_pressed(self):
        if self.running_benchmark:
            return False
        
        if sys.stdin.isatty():
            rlist, _, _ = select.select([sys.stdin], [], [], 0)
            if rlist:
                line = sys.stdin.readline()
                if line:
                    return True
        return False

    def send_request(self, transaction_str):
        self.timestamp_counter += 1
        # ts = int(time.time() * 1000) + self.timestamp_counter 
        ts = self.timestamp_counter
        parts = transaction_str.strip('() ').split(',')
        if len(parts) == 1:
            op_type = pbft_pb2.OperationType.BALANCE
            sender = parts[0].strip()
            receiver = ""
            amount = 0
        elif len(parts) == 3:
            op_type = pbft_pb2.OperationType.TRANSFER
            sender = parts[0].strip()
            receiver = parts[1].strip()
            amount = int(parts[2].strip())
        else:
            print(f"Invalid transaction: {transaction_str}")
            return False

        if sender != self.client_id:
            print(f"Sender mismatch for client {self.client_id}: {transaction_str}")
            return False

        request = pbft_pb2.Request(
            type=op_type,
            sender=sender,
            receiver=receiver,
            amount=amount,
            timestamp=ts
        )
        self.sign_message(request)

        print(f"[Client {self.client_id}] Sending request ts={ts}, type={'BALANCE' if op_type == pbft_pb2.OperationType.BALANCE else 'TRANSFER'}")

        quorum = config.TWO_F_PLUS_ONE if op_type == pbft_pb2.OperationType.BALANCE else config.F_PLUS_ONE
        quorum_reached = [False] 
        with self.lock:
            self.pending_replies[ts] = []
            self.pending_quorums[ts] = quorum

        if op_type == pbft_pb2.OperationType.BALANCE:
            print(f"[Client {self.client_id}] Broadcasting BALANCE query to all nodes")
            for nid, stub in self.stubs.items():
                with self.lock:
                    if ts not in self.pending_replies or self.check_quorum(ts, quorum):
                        break
                
                try:
                    stub.SendRequest(request, timeout=1.5) 
                except:
                    pass
        else:
            nodes_to_try = [self.leader] + [nid for nid in config.NODE_IDS if nid != self.leader]
            request_accepted = False
            for nid in nodes_to_try:
                try:
                    response = self.stubs[nid].SendRequest(request, timeout=4.0)
                    if response.data == "ACCEPTED":
                        request_accepted = True
                        break
                    else:
                        print(f"[Client {self.client_id}] {nid} rejected: {response.data}, trying next node...")
                except:
                    print(f"[Client {self.client_id}] {nid} not responding, trying next node...")
            
            if not request_accepted:
                print(f"[Client {self.client_id}] No nodes responding! Request may be lost.")

        with self.lock:
            if ts not in self.pending_replies or self.check_quorum(ts, quorum):
                return True


        self.stop_retries = False

        for retry in range(config.MAX_RETRIES + 1):
            if self.check_enter_pressed():
                self.stop_retries = True
                break
            
            wait_start = time.time()
            while time.time() - wait_start < config.REQUEST_TIMEOUT:     
                with self.lock:
                    if self.check_quorum(ts, quorum):
                        quorum_reached[0] = True
                        return True
                time.sleep(0.1)
                
                if quorum_reached[0]:
                    return True

            
            with self.lock:
                if ts not in self.pending_replies:
                    return True
                if self.check_quorum(ts, quorum):
                    return True
            
            if retry < config.MAX_RETRIES:
                print(f"Timeout! Retry {retry + 1}/{config.MAX_RETRIES}: {transaction_str}")
                for nid, stub in self.stubs.items():
                    if self.check_enter_pressed():
                        self.stop_retries = True
                        break
                        
                    time.sleep(1.5)
                    with self.lock:
                        if ts not in self.pending_replies or self.check_quorum(ts, quorum):
                            return True
                    try:
                        response = stub.SendRequest(request, timeout=1.0)
                        if response.data == "ACCEPTED":
                            pass
                    except:
                        pass
                

                if self.stop_retries:
                    break
        
        
        print(f"Transaction timeout: {transaction_str}")
        with self.lock:
            if ts in self.pending_replies:
                del self.pending_replies[ts]
            if ts in self.pending_quorums:
                del self.pending_quorums[ts]
        return False
    
    def send_smallbank_request(self, operation_str):
        self.running_benchmark = True
        self.timestamp_counter += 1
        ts = self.timestamp_counter
        
        request = pbft_pb2.Request(
            sender=self.client_id,
            receiver=operation_str,
            amount=0,
            timestamp=ts
        )
        
        self.sign_message(request)
        
        print(f"[SmallBank] Client {self.client_id} sending request ts={ts}, operation={operation_str[:50]}...")
        
        quorum_reached = [False]
        quorum = config.F_PLUS_ONE
        
        with self.lock:
            self.pending_replies[ts] = []
            self.pending_quorums[ts] = quorum
        
        leader = config.get_leader(1)
        nodes_to_try = [leader] + [nid for nid in config.NODE_IDS if nid != leader]
        request_accepted = False
        
        for nid in nodes_to_try:
            try:
                response = self.stubs[nid].SendRequest(request, timeout=4.0)
                if response.data == "ACCEPTED":
                    request_accepted = True
                    break
            except:
                continue
        
        if not request_accepted:
            with self.lock:
                if ts in self.pending_replies:
                    del self.pending_replies[ts]
                if ts in self.pending_quorums:
                    del self.pending_quorums[ts]
            return False
        
        wait_start = time.time()
        while time.time() - wait_start < config.REQUEST_TIMEOUT:
            with self.lock:
                if self.check_quorum(ts, quorum):
                    return True
            time.sleep(0.1)
        
        with self.lock:
            if ts in self.pending_replies:
                del self.pending_replies[ts]
            if ts in self.pending_quorums:
                del self.pending_quorums[ts]
        return False

    def SendReply(self, reply, context):
        with self.lock:
            ts = reply.timestamp
            if ts in self.pending_replies:
                self.pending_replies[ts].append(reply)
                print(f"[Client] Received reply from {reply.node_id} for ts={ts}, result={reply.result}, total={len(self.pending_replies[ts])}")
                quorum = self.pending_quorums.get(ts, config.F_PLUS_ONE)
                self.check_quorum(ts, quorum, delete_on_quorum=not self.running_benchmark)
        return pbft_pb2.Empty()

    def check_quorum(self, ts, quorum, delete_on_quorum=True):
        replies = self.pending_replies.get(ts, [])
        results = {}
        for r in replies:
            if self.validate_signature(r, self.public_keys[r.node_id]):
                results[r.result] = results.get(r.result, 0) + 1
                if r.view > self.current_view:
                    self.current_view = r.view
                    self.leader = config.get_leader(self.current_view)
        for result, count in results.items():
            if count >= quorum:
                if delete_on_quorum:
                    print(f"QUORUM REACHED for ts={ts}: result='{result}' with {count}/{quorum} replies")
                    del self.pending_replies[ts]
                    if ts in self.pending_quorums:
                        del self.pending_quorums[ts]
                return True
        return False

class ClientServicer(client_pb2_grpc.ClientServiceServicer):
    def __init__(self, clients):
        self.clients = clients
    
    def SendReply(self, reply, context):
        client_id = reply.client_id
        if client_id in self.clients:
            return self.clients[client_id].SendReply(reply, context)
        return pbft_pb2.Empty()

class PBFTMultiClientController:
    def __init__(self):
        self.server_processes: Dict[str, subprocess.Popen] = {}
        self.clients: Dict[str, Client] = {}
        self.stubs = {}
        self._update_stubs()
        self.server = grpc.server(ThreadPoolExecutor(max_workers=10))
        for cid in config.CLIENT_IDS:
            self.clients[cid] = Client(cid, self)
        
        client_servicer = ClientServicer(self.clients)
        client_pb2_grpc.add_ClientServiceServicer_to_server(client_servicer, self.server)
        self.server.add_insecure_port(f'localhost:{config.CLIENT_PORT}')
        self.server.start()
        print(f"[PBFTMultiClientController] Initialized {len(self.clients)} clients and client server")
    
    def _update_stubs(self):
        self.stubs = {}
        for nid in config.NODE_IDS:
            try:
                node_num = int(nid[1:])
                channel = grpc.insecure_channel(config.NODE_ADDRESSES[node_num])
                self.stubs[nid] = pbft_pb2_grpc.PbftServiceStub(channel)
            except Exception as e:
                print(f"Warning: Could not create stub for node {nid}: {e}")

    def start_servers_in_terminals(self, node_ids: List[str] = None):
        if node_ids is None:
            node_ids = config.NODE_IDS
        
        for nid in node_ids:
            try:
                src_path = f"{os.getcwd()}/src"
                python_cmd = f"PYTHONPATH={src_path} {sys.executable} src/server/main.py {nid}"
                terminal_script = f'tell app "Terminal" to do script "cd {os.getcwd()} && {python_cmd}"'
                os.system(f"osascript -e '{terminal_script}' > /dev/null 2>&1 &")
                print(f"Started node {nid} in new terminal")
                time.sleep(0.5)
            except Exception as e:
                print(f"Failed to start node {nid} in terminal: {e}")
        time.sleep(0.5)

    def set_mode(self, nid: str, live: bool, byzantine: bool, attack: str):
        if nid in self.stubs:
            try:
                request = pbft_pb2.ModeRequest(live=live, byzantine=byzantine, attack=attack)
                self.stubs[nid].SetMode(request)
            except grpc.RpcError as e:
                print(f"Failed to set mode for {nid}: {e.details()}")

    def reset_all(self):
        for stub in self.stubs.values():
            try:
                stub.Reset(pbft_pb2.Empty())
            except:
                pass
        
        for client in self.clients.values():
            with client.lock:
                client.current_view = 1
                client.leader = config.get_leader(client.current_view)
                client.timestamp_counter = 0
                client.pending_replies.clear()
                client.pending_quorums.clear()

    def print_log(self, nid: str):
        log_file = f"logs/server_{nid}.log"
        if os.path.exists(log_file):
            try:
                with open(log_file, 'r') as f:
                    content = f.read()
                    if content:
                        print(f"\n=== Log file for {nid} ===")
                        print(content)
                    else:
                        print(f"Log file for {nid} is empty")
            except Exception as e:
                print(f"Error reading log file for {nid}: {e}")
        else:
            print(f"Log file not found: {log_file}")

    def print_log_t(self, nid: str):
        try:
            if nid in self.stubs:
                response = self.stubs[nid].PrintLog(pbft_pb2.Empty())
                print(response.data)
            else:
                print(f"Node {nid} is not available")
        except grpc.RpcError as e:
            print(f"Failed to get transaction log from {nid}: {e.details()}")

    def print_db(self, nid: str):
        if nid.lower() == 'all':
            print(f"\n=== Database for all nodes ===")
            for node_id in config.NODE_IDS:
                try:
                    if node_id in self.stubs:
                        response = self.stubs[node_id].PrintDB(pbft_pb2.Empty())
                        print(f"\n[{node_id}]:")
                        print(response.data)
                    else:
                        print(f"\n[{node_id}]: Not available")
                except grpc.RpcError as e:
                    print(f"\n[{node_id}]: Error - {e.details()}")
            print("=" * 50)
        else:
            try:
                if nid in self.stubs:
                    response = self.stubs[nid].PrintDB(pbft_pb2.Empty())
                    print(response.data)
                else:
                    print(f"Node {nid} is not available")
            except grpc.RpcError as e:
                print(f"Failed to get db from {nid}: {e.details()}")

    def print_status(self, nid: str, seq: int):
        try:
            if nid in self.stubs:
                request = pbft_pb2.SeqRequest(seq=seq)
                response = self.stubs[nid].PrintStatus(request)
                print(response.data)
            else:
                print(f"Node {nid} is not available")
        except grpc.RpcError as e:
            print(f"Failed to get status from {nid}: {e.details()}")
    
    def print_status_all(self, seq: int):
        print(f"\n=== Status for seq {seq} from all nodes ===")
        for nid in config.NODE_IDS:
            try:
                if nid in self.stubs:
                    request = pbft_pb2.SeqRequest(seq=seq)
                    response = self.stubs[nid].PrintStatus(request)
                    print(f"{nid}: {response.data}")
                else:
                    print(f"{nid}: Not available")
            except grpc.RpcError as e:
                print(f"{nid}: Error - {e.details()}")
        print("=" * 50)

    def print_view(self, nid: str):
        if nid.lower() == 'all':
            print(f"\n=== View information for all nodes ===")
            for node_id in config.NODE_IDS:
                try:
                    if node_id in self.stubs:
                        response = self.stubs[node_id].PrintView(pbft_pb2.Empty())
                        print(f"\n[{node_id}]:")
                        print(response.data)
                    else:
                        print(f"\n[{node_id}]: Not available")
                except grpc.RpcError as e:
                    print(f"\n[{node_id}]: Error - {e.details()}")
            print("=" * 50)
        else:
            try:
                if nid in self.stubs:
                    response = self.stubs[nid].PrintView(pbft_pb2.Empty())
                    print(response.data)
                else:
                    print(f"Node {nid} is not available")
            except grpc.RpcError as e:
                print(f"Failed to get view from {nid}: {e.details()}")

    def parse_live_or_byz(self, str_list):
        if not str_list or str_list.strip() == '':
            return []
        str_list = str_list.strip('[] ')
        return [n.strip() for n in str_list.split(',') if n.strip()]

    def run_test_cases(self, csv_filename: str, specific_sets: List[int] = None):
        if specific_sets:
            print(f"Running specific sets: {specific_sets}")
        else:
            print("Running all test sets")
        
        try:
            with open(csv_filename, 'r') as file:
                reader = csv.DictReader(file)
                rows = list(reader)
            
            current_set = None
            set_transactions = []
            set_live = []
            set_byz = []
            set_attack = ''
            executed_count = 0
            
            for row in rows:
                set_num = row.get('Set Number', '').strip()
                transaction = row.get('Transactions', '').strip()
                live_str = row.get('Live', '').strip()
                byz_str = row.get('Byzantine', '').strip()
                attack = row.get('Attack', '').strip()
                
                if set_num != '':
                    if current_set is not None:
                        if specific_sets is None or int(current_set) in specific_sets:
                            self._execute_test_set(current_set, set_transactions, set_live, set_byz, set_attack)
                            executed_count += 1
                        set_transactions = []
                    
                    current_set = set_num
                    set_live = self.parse_live_or_byz(live_str)
                    set_byz = self.parse_live_or_byz(byz_str)
                    set_attack = attack.strip('[] ')
                    
                    if transaction != '':
                        set_transactions.append(transaction)
                else:
                    if transaction != '':
                        set_transactions.append(transaction)
            
            if current_set is not None:
                if specific_sets is None or int(current_set) in specific_sets:
                    self._execute_test_set(current_set, set_transactions, set_live, set_byz, set_attack)
                    executed_count += 1
            
            print(f"Executed {executed_count} test set(s)")
        except FileNotFoundError:
            print(f"Error: File '{csv_filename}' not found")
        except Exception as e:
            print(f"Error running test cases: {e}")

    def _execute_test_set(self, set_num, transactions, live_nodes, byz_nodes, attack):
        self.reset_all()
        
        print(f"\nEXECUTING TEST SET {set_num}")
        print(f"Transactions: {len(transactions)}")
        print(f"Live: {live_nodes}")
        print(f"Byzantine: {byz_nodes}")
        print(f"Attack: {attack}")
        
        for nid in config.NODE_IDS:
            is_live = nid in live_nodes
            is_byz = nid in byz_nodes
            self.set_mode(nid, is_live, is_byz, attack)

        for tx_str in transactions:
            parsed = self.parse_transaction(tx_str)
            if parsed:
                sender = parsed[0]
                if sender in self.clients:
                    print(f"Submitting: {tx_str}")
                    self.clients[sender].send_request(tx_str)

        print(f"TEST SET {set_num} COMPLETED\n")

    def parse_transaction(self, tx_str):
        tx_str = tx_str.strip().replace('(', '').replace(')', '')
        parts = [p.strip() for p in tx_str.split(',')]
        if len(parts) == 1:
            return (parts[0],)  # balance
        elif len(parts) == 3:
            try:
                amount = int(parts[2])
                return (parts[0], parts[1], amount)
            except ValueError:
                return None
        return None

def main():
    controller = PBFTMultiClientController()
    
    help_text = """
Available Commands:
=== Server Management ===
  start [n1 n2...]  - Start nodes in separate terminals

=== Manual Testing ===
  submit sender receiver amount  - Submit transfer (e.g., submit A B 3)
  submit sender                  - Query balance (e.g., submit A)

=== Test Execution ===
  runtest filename.csv      - Run all test sets from CSV
  runset sample_test.csv set_nums - Run specific sets (e.g., 1,3)

=== Debug/Print Commands ===
  printlog nid              - Print actual log file for node (server_nid.log)
  printlog_t nid            - Print transaction log for node (in-memory)
  printdb nid               - Print database for node
  printdb all               - Print database for ALL nodes
  printstatus seq           - Print status for sequence from ALL nodes
  printstatus_node nid seq  - Print status for sequence from specific node
  printview nid             - Print view changes for node
  printview all             - Print view information for ALL nodes

=== General ===
  help                      - Show this help
  exit/quit                 - Exit
"""

    print("Linear-PBFT Distributed System Controller")
    print("Type 'help' for commands\n")
    
    while True:
        try:
            command = input("PBFT> ").strip().split()
            if not command:
                continue
            
            cmd = command[0].lower()
            args = command[1:]
            
            if cmd in ['exit', 'quit']:
                print("Shutting down...")
                break
            
            elif cmd == 'help':
                print(help_text)
            
            elif cmd == 'start':
                node_ids = args if args else None
                controller.start_servers_in_terminals(node_ids)
            
            elif cmd == 'submit':
                if len(args) == 1:
                    # Balance query: submit A
                    sender = args[0].upper()
                    if sender not in config.CLIENT_IDS:
                        print(f"Invalid client ID: {sender}")
                        continue
                    transaction = f"({sender})"
                    print(f"Submitting balance query: {transaction}")
                    success = controller.clients[sender].send_request(transaction)
                    if success:
                        print("Query completed successfully")
                    else:
                        print("Query failed (timeout or no quorum)")
                elif len(args) == 3:
                    # Transfer: submit A B 3
                    sender = args[0].upper()
                    receiver = args[1].upper()
                    try:
                        amount = int(args[2])
                        if sender not in config.CLIENT_IDS or receiver not in config.CLIENT_IDS:
                            print(f"Invalid client ID(s): {sender}, {receiver}")
                            continue
                        transaction = f"({sender}, {receiver}, {amount})"
                        print(f"Submitting transfer: {transaction}")
                        success = controller.clients[sender].send_request(transaction)
                        if success:
                            print("Transaction completed successfully")
                        else:
                            print("Transaction failed (timeout or no quorum)")
                    except ValueError:
                        print("Invalid amount")
                else:
                    print("Usage: submit sender [receiver amount]")
                    print("  Balance: submit A")
                    print("  Transfer: submit A B 3")
            
            elif cmd == 'runtest':
                if len(args) != 1:
                    print("Usage: runtest filename.csv")
                    continue
                controller.run_test_cases(args[0])
            
            elif cmd == 'runset':
                if len(args) < 1:
                    print("Usage: runset filename.csv [set_numbers]")
                    continue
                filename = args[0]
                if len(args) > 1:
                    try:
                        set_nums = [int(s.strip()) for s in args[1].split(',')]
                        controller.run_test_cases(filename, set_nums)
                    except ValueError:
                        print("Invalid set numbers")
                else:
                    controller.run_test_cases(filename)
            
            elif cmd == 'printlog':
                if len(args) != 1:
                    print("Usage: printlog nid")
                    continue
                controller.print_log(args[0])
            
            elif cmd == 'printlog_t':
                if len(args) != 1:
                    print("Usage: printlog_t nid")
                    continue
                controller.print_log_t(args[0])
            
            elif cmd == 'printdb':
                if len(args) != 1:
                    print("Usage: printdb <nid|all>")
                    continue
                controller.print_db(args[0])
            
            elif cmd == 'printstatus':
                if len(args) != 1:
                    print("Usage: printstatus seq")
                    continue
                try:
                    seq = int(args[0])
                    controller.print_status_all(seq)
                except ValueError:
                    print("Invalid sequence number")
            
            elif cmd == 'printstatus_node':
                if len(args) != 2:
                    print("Usage: printstatus_node nid seq")
                    continue
                try:
                    seq = int(args[1])
                    controller.print_status(args[0], seq)
                except ValueError:
                    print("Invalid sequence number")
            
            elif cmd == 'printview':
                if len(args) != 1:
                    print("Usage: printview <nid|all>")
                    continue
                controller.print_view(args[0])
            
            else:
                print(f"Unknown command: {cmd}")
        
        except KeyboardInterrupt:
            print("\nUse 'exit' to shutdown.")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == '__main__':
    main()