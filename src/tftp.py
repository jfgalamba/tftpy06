"""
This module handles all TFTP related "stuff": data structures, packet 
definitions, methods and protocol operations.

(C) João Galamba, 2023
"""

import ipaddress
import re
import struct
import string
from socket import (
    socket,
    herror,
    gaierror,
    gethostbyaddr,
    gethostbyname_ex,
    AF_INET, SOCK_DGRAM,
)

###############################################################
##
##      PROTOCOL CONSTANTS AND TYPES
##
###############################################################

MAX_DATA_LEN = 512            # bytes
MAX_BLOCK_NUMBER = 2**16 - 1  # 0..65535
INACTIVITY_TIMEOUT = 25.0     # segs
DEFAULT_MODE = 'octet'
DEFAULT_BUFFER_SIZE = 8192    # bytes

# TFTP message opcodes
# RRQ, WRQ, DAT, ACK, ERR = range(1, 6)
RRQ = 1   # Read Request
WRQ = 2   # Write Request
DAT = 3   # Data transfer
ACK = 4   # Acknowledge DAT
ERR = 5   # Error packet; what the server responds if a read/write 
          # can't be processed, read and write errors during file 
          # transmission also cause this message to be sent, and 
          # transmission is then terminated. The error number gives a 
          # numeric error code, followed by an ASCII error message that
          # might contain additional, operating system specific 
          # information.

ERR_NOT_DEFINED = 0
ERR_FILE_NOT_FOUND = 1
ERR_ACCESS_VIOLATION = 2
# Acresentar códigos de erro em falta

ERROR_MESSAGES = {
    ERR_NOT_DEFINED: 'Not defined, see error message (if any)',
    ERR_FILE_NOT_FOUND: 'File not found',
    ERR_ACCESS_VIOLATION: 'Access violation',
    # Acresentar mensagens em falta
}

INET4Address = tuple[str, int]        # TCP/UDP address => IPv4 and port

###############################################################
##
##      PACKET PACKING AND UNPACKING
##
###############################################################

def pack_rrq(filename: str, mode: str = DEFAULT_MODE):
    return pack_rrq_wrq(RRQ, filename, mode)
#:

def pack_wrq(filename: str, mode: str = DEFAULT_MODE):
    return pack_rrq_wrq(WRQ, filename, mode)
#:

def pack_rrq_wrq(opcode: int, filename: str, mode: str):
    if not is_ascii_printable(filename):
        raise ValueError(f"Invalid filename: {filename}. Not ASCII printable.")
    encoded_filename = filename.encode() + b'\x00'
    encoded_mode = mode.encode() + b'\x00'
    fmt = f'!H{len(encoded_filename)}s{len(encoded_mode)}s'
    return struct.pack(fmt, opcode, encoded_filename, encoded_mode)
#:

def unpack_rrq(packet: bytes) -> tuple[str, str]:
    return unpack_rrq_wrq(RRQ, packet)
#:

def unpack_wrq(packet: bytes) -> tuple[str, str]:
    return unpack_rrq_wrq(WRQ, packet)
#:

def unpack_rrq_wrq(opcode: int, packet: bytes) -> tuple[str, str]:
    received_opcode = unpack_opcode(packet)
    if received_opcode != opcode:
        raise ValueError(f"Invalid opcode: {received_opcode}. Expected opcode: {opcode}")
    delim_pos = packet.index(b'\x00', 2)
    filename = packet[2:delim_pos].decode()
    mode = packet[delim_pos + 1:-1].decode()
    return (filename, mode)
#:

def unpack_opcode(packet: bytes) -> int:
    opcode = struct.unpack('!H', packet[:2])[0]
    if opcode not in (RRQ, WRQ, DAT, ACK, ERR):
        raise ValueError(f"Invalid opcode {opcode}")
    return opcode
#:

###############################################################
##
##      ERRORS AND EXCEPTIONS
##
###############################################################

class NetworkError(Exception):
    """
    Any network error, like "host not found", timeouts, etc.
    """
#:

class ProtocolError(NetworkError):
    """
    A protocol error like unexpected or invalid opcode, wrong block 
    number, or any other invalid protocol parameter.
    """
#:

class Err(Exception):
    """
    An error sent by the server. It may be caused because a read/write 
    can't be processed. Read and write errors during file transmission 
    also cause this message to be sent, and transmission is then 
    terminated. The error number gives a numeric error code, followed 
    by an ASCII error message that might contain additional, operating 
    system specific information.
    """
    def __init__(self, error_code: int, error_msg: str):
        super().__init__(f'TFTP Error {error_code}')
        self.error_code = error_code
        self.error_msg = error_msg
    #:
#:

################################################################################
##
##      COMMON UTILITIES
##      Mostly related to network tasks
##
################################################################################

def _make_is_valid_hostname():
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    def _is_valid_hostname(hostname):
        """
        From: http://stackoverflow.com/questions/2532053/validate-a-hostname-string
        See also: https://en.wikipedia.org/wiki/Hostname (and the RFC 
        referenced there)
        """
        if len(hostname) > 255:
            return False
        if hostname[-1] == ".":
            # strip exactly one dot from the right, if present
            hostname = hostname[:-1]
        return all(allowed.match(x) for x in hostname.split("."))
    return _is_valid_hostname
#:
is_valid_hostname = _make_is_valid_hostname()


def get_host_info(server_addr: str) -> tuple[str, str]:
    """
    Returns the server ip and hostname for server_addr. This param may
    either be an IP address, in which case this function tries to query
    its hostname, or vice-versa.
    This functions raises a ValueError exception if the host name in
    server_addr is ill-formed, and raises NetworkError if we can't get
    an IP address for that host name.
    TODO: refactor code...
    """
    try:
        ipaddress.ip_address(server_addr)
    except ValueError:
        # server_addr not a valid ip address, then it might be a 
        # valid hostname
        # pylint: disable=raise-missing-from
        if not is_valid_hostname(server_addr):
            raise ValueError(f"Invalid hostname: {server_addr}.")
        server_name = server_addr
        try:
            # gethostbyname_ex returns the following tuple: 
            # (hostname, aliaslist, ipaddrlist)
            server_ip = gethostbyname_ex(server_name)[2][0]
        except gaierror:
            raise NetworkError(f"Unknown server: {server_name}.")
    else:  
        # server_addr is a valid ip address, get the hostname
        # if possible
        server_ip = server_addr
        try:
            # returns a tuple like gethostbyname_ex
            server_name = gethostbyaddr(server_ip)[0]
        except herror:
            server_name = ''
    return server_ip, server_name
#:

def is_ascii_printable(txt: str) -> bool:
    return set(txt).issubset(string.printable)
    # ALTERNATIVA: return not set(txt) - set(string.printable)
#:
