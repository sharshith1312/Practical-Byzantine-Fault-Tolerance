"""
Author: sharshith1312
Course: CSE535 - Distributed Systems
"""

import sys
import time
from concurrent import futures
import grpc
from shared import config
from server.node import Node
from server.service import PbftServicer
import signal

from protos import pbft_pb2_grpc

def serve(node_id):
    node = Node(node_id)
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=50))
    pbft_pb2_grpc.add_PbftServiceServicer_to_server(PbftServicer(node), server)
    node_num = int(node_id[1:]) if isinstance(node_id, str) and node_id.startswith('n') else int(node_id)
    port = config.NODE_ADDRESSES[node_num]
    server.add_insecure_port(port)
    server.start()

    node.logger.info(f"Server started, listening on {port}")
    # Setup graceful shutdown
    def signal_handler(signum, frame):
        node.logger.info(f"Server received shutdown signal")
        server.stop(grace=2)
        node.logger.info("Server shutdown complete")
    
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        node.logger.info("Server interrupted")
        server.stop(grace=2)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python -m src.server.main <node_id>")
        sys.exit(1)
    node_id = sys.argv[1]  # Can be 'n1' or '1'
    serve(node_id)