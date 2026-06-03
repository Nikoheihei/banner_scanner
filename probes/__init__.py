from .ssh import probe_ssh
from .ftp import probe_ftp
from .telnet import probe_telnet

PROTOCOL_PROBES = {
    "ssh": probe_ssh,
    "ftp": probe_ftp,
    "telnet": probe_telnet,
}
