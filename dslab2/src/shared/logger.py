"""
Author: sharshith1312
Course: CSE535 - Distributed Systems
"""

import logging
import os

def setup_logger(node_id):

    logger_name = f"Node{node_id}"
    logger = logging.getLogger(logger_name)
    log_level = logging.DEBUG
    # log_level = logging.INFO
    logger.handlers.clear()
    
    logger.setLevel(log_level)
    
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    
    log_file = os.path.join(log_dir, f"server_{node_id}.log")
    
    file_handler = logging.FileHandler(log_file, mode='w')
    file_handler.setLevel(log_level)
    
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    
    formatter = logging.Formatter(
        fmt='%(asctime)s - [Node %(node_id)s] - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    old_factory = logging.getLogRecordFactory()
    
    def record_factory(*args, **kwargs):
        record = old_factory(*args, **kwargs)
        record.node_id = node_id
        return record
    
    logging.setLogRecordFactory(record_factory)
    
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    logger.propagate = False
    
    return logger

def clear_log(logger):
    for handler in logger.handlers:
        if isinstance(handler, logging.FileHandler):
            try:
                handler.acquire()
                handler.stream.seek(0)
                handler.stream.truncate()
                handler.release()
            except Exception as e:
                handler.release()
                logger.error(f"Failed to clear log file: {e}")

