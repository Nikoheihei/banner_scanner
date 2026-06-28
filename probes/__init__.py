from .ssh import probe_ssh
from .ftp import probe_ftp
from .telnet import probe_telnet
from .redis import probe_redis
from .mysql import probe_mysql
from .pgsql import probe_pgsql

PROTOCOL_PROBES = {
    "ssh": probe_ssh,
    "ftp": probe_ftp,
    "telnet": probe_telnet,
    "redis": probe_redis,
    "mysql": probe_mysql,
    "pgsql": probe_pgsql,
}
