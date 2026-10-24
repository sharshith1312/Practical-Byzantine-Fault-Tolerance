N = 7
F = 2
QUORUM = 2 * F + 1
F_PLUS_ONE = F + 1
TWO_F_PLUS_ONE = 2 * F + 1
THREE_F_PLUS_ONE = 3 * F + 1

# Timeeout in Seconds
VIEW_CHANGE_TIMEOUT = 3.0 
REQUEST_TIMEOUT = 1.5 
MAX_RETRIES = 3 

NODE_ADDRESSES = {i: f"localhost:5005{i}" for i in range(1, N + 1)}
CLIENT_PORT = 60000

NODE_IDS = [f'n{i}' for i in range(1, N + 1)]
CLIENT_IDS = list('ABCDEFGHIJ')

INITIAL_BALANCE = 10

LOG_DIR = '../logs'

TA_DELAY = 0.3

# Threshold Signature Scheme (TSS) configuration  
USE_THRESHOLD_SIGNATURES = True  # Enable/disable TSS optimization

# Checkpointing configuration
CHECKPOINT_INTERVAL = 10
USE_CHECKPOINTING = True  # Enable/disable checkpointing mechanism

def get_leader(view):
    return NODE_IDS[(view - 1) % N]