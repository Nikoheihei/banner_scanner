"""Evaluation catalog for protocol software and platform labels.

The scanner may emit many kinds of evidence: software products, managed
services, device vendors, built-in OS services, and protocol-only facts.  Active
evaluation intentionally uses only concrete software/platform labels whose
historical banners can be sampled and re-probed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SoftwareClass:
    protocol: str
    label: str
    category: str
    official_url: str
    aliases: tuple[str, ...] = ()
    evaluation_eligible: bool = True


SOFTWARE_CLASSES: tuple[SoftwareClass, ...] = (
    # FTP independent software and MFT platforms observed through FTP.
    SoftwareClass("FTP", "vsFTPd", "independent_software", "https://security.appspot.com/vsftpd.html"),
    SoftwareClass("FTP", "Pure-FTPd", "independent_software", "https://www.pureftpd.org/project/pure-ftpd/"),
    SoftwareClass("FTP", "ProFTPD", "independent_software", "https://www.proftpd.org/"),
    SoftwareClass("FTP", "FileZilla Server", "independent_software", "https://filezilla-project.org/"),
    SoftwareClass("FTP", "Microsoft FTP", "independent_software", "https://learn.microsoft.com/en-us/iis/publish/using-the-ftp-service/"),
    SoftwareClass("FTP", "Serv-U FTP", "independent_software", "https://www.solarwinds.com/serv-u", ("Serv-U",)),
    SoftwareClass("FTP", "Core FTP Server", "independent_software", "https://www.coreftp.com/server/", ("Core FTP",)),
    SoftwareClass("FTP", "Cerberus FTP", "independent_software", "https://www.cerberusftp.com/", ("Cerberus",)),
    SoftwareClass("FTP", "CrushFTP", "independent_software", "https://www.crushftp.com/"),
    SoftwareClass("FTP", "Wing FTP", "independent_software", "https://www.wftpserver.com/"),
    SoftwareClass("FTP", "WS_FTP", "independent_software", "https://www.progress.com/ws_ftp", ("WS_FTP Server",)),
    SoftwareClass("FTP", "SFTPGo", "independent_software", "https://sftpgo.com/"),
    SoftwareClass("FTP", "xlightftpd", "independent_software", "https://www.xlightftpd.com/", ("Xlight FTP", "Xlight FTP Server")),
    SoftwareClass("FTP", "PCMan FTP Server", "independent_software", "https://sourceforge.net/projects/pcmanftpd/"),
    SoftwareClass("FTP", "FileZilla Pro Enterprise", "independent_software", "https://filezillapro.com/", ("FileZilla Pro",)),
    SoftwareClass("FTP", "CompleteFTP", "independent_software", "https://enterprisedt.com/products/completeftp/"),
    SoftwareClass("FTP", "Rumpus", "independent_software", "https://www.maxum.com/Rumpus/"),
    SoftwareClass("FTP", "Syncplify Server", "independent_software", "https://www.syncplify.com/", ("Syncplify",)),
    SoftwareClass("FTP", "zFTPServer", "independent_software", "https://www.provideserver.com/", ("ProVide", "zFTPServer/ProVide")),
    SoftwareClass("FTP", "FileCOPA", "independent_software", "https://www.filecopa.com/"),
    SoftwareClass("FTP", "GoAnywhere", "mft_platform", "https://www.goanywhere.com/", ("GoAnywhere FTP",)),

    # SSH independent software and MFT platforms observed through SSH.
    SoftwareClass("SSH", "OpenSSH", "independent_software", "https://www.openssh.com/"),
    SoftwareClass("SSH", "Dropbear", "independent_software", "https://matt.ucc.asn.au/dropbear/dropbear.html", ("Dropbear SSH",)),
    SoftwareClass("SSH", "Bitvise SSH Server", "independent_software", "https://www.bitvise.com/ssh-server", ("Bitvise", "WinSSHD")),
    SoftwareClass("SSH", "Serv-U", "independent_software", "https://www.solarwinds.com/serv-u"),
    SoftwareClass("SSH", "Cerberus FTP", "independent_software", "https://www.cerberusftp.com/", ("Cerberus FTP Server",)),
    SoftwareClass("SSH", "WS_FTP", "independent_software", "https://www.progress.com/ws_ftp", ("WS_FTP Server",)),
    SoftwareClass("SSH", "CrushFTP", "independent_software", "https://www.crushftp.com/"),
    SoftwareClass("SSH", "SFTPGo", "independent_software", "https://sftpgo.com/"),
    SoftwareClass("SSH", "Maverick SSHD", "independent_software", "https://www.jadaptive.com/"),
    SoftwareClass("SSH", "Wing FTP", "independent_software", "https://www.wftpserver.com/"),
    SoftwareClass("SSH", "VShell", "independent_software", "https://www.vandyke.com/products/vshell/"),
    SoftwareClass("SSH", "mod_sftp", "independent_software", "https://www.proftpd.org/docs/contrib/mod_sftp.html"),
    SoftwareClass("SSH", "SFTPPlus", "independent_software", "https://www.sftpplus.com/"),
    SoftwareClass("SSH", "SSHPiper", "independent_software", "https://github.com/tg123/sshpiper"),
    SoftwareClass("SSH", "xlightftpd", "independent_software", "https://www.xlightftpd.com/"),
    SoftwareClass("SSH", "RebexSSH", "independent_software", "https://www.rebex.net/file-server/"),
    SoftwareClass("SSH", "Pragma Fortress SSH", "independent_software", "https://www.pragmasys.com/", ("Pragma/Fortress SSH", "Fortress SSH")),
    SoftwareClass("SSH", "SilverSHielD", "independent_software", "http://www.k2sxs.com/silvershield/"),
    SoftwareClass(
        "SSH", "FreSSH", "independent_software", "https://www.freesshd.com/",
        evaluation_eligible=False,
    ),
    SoftwareClass("SSH", "Sysax SSH", "independent_software", "https://www.sysax.com/server/"),
    SoftwareClass("SSH", "WRQ Reflection", "independent_software", "https://www.opentext.com/products/reflection-for-secure-it", ("WRQ Reflection for Secure IT", "Reflection for Secure IT")),
    SoftwareClass("SSH", "CoreSSH", "independent_software", "https://www.coreftp.com/"),
    SoftwareClass("SSH", "Core FTP", "independent_software", "https://www.coreftp.com/server/"),
    SoftwareClass("SSH", "FileZilla Pro Enterprise Server", "independent_software", "https://filezillapro.com/"),
    SoftwareClass("SSH", "Syncplify Server", "independent_software", "https://www.syncplify.com/", ("Syncplify",)),
    SoftwareClass("SSH", "CompleteFTP", "independent_software", "https://enterprisedt.com/products/completeftp/"),
    SoftwareClass("SSH", "FileCOPA", "independent_software", "https://www.filecopa.com/"),
    SoftwareClass("SSH", "zFTPServer", "independent_software", "https://www.provideserver.com/", ("ProVide", "zFTPServer/ProVide")),
    SoftwareClass("SSH", "VersaSSH", "independent_software", "https://versa-networks.com/"),
    SoftwareClass("SSH", "GoAnywhere", "mft_platform", "https://www.goanywhere.com/"),
    SoftwareClass("SSH", "MOVEit", "mft_platform", "https://www.progress.com/moveit", ("MOVEit Transfer",)),
    SoftwareClass("SSH", "JSCAPE", "mft_platform", "https://www.jscape.com/"),
    SoftwareClass("SSH", "Informatica MFT", "mft_platform", "https://www.informatica.com/"),
    SoftwareClass("SSH", "Cleo", "mft_platform", "https://www.cleo.com/"),
    SoftwareClass("SSH", "FileMage Gateway", "mft_platform", "https://www.filemage.io/"),

    # Database implementations.
    SoftwareClass("MYSQL", "MariaDB", "database_implementation", "https://mariadb.com/"),
    SoftwareClass("MYSQL", "Percona Server", "database_implementation", "https://www.percona.com/mysql/software/percona-server-for-mysql"),
    SoftwareClass("MYSQL", "TiDB", "database_implementation", "https://www.pingcap.com/tidb/"),
    SoftwareClass("PGSQL", "Amazon Redshift", "database_implementation", "https://aws.amazon.com/redshift/"),
    SoftwareClass("PGSQL", "CrateDB", "database_implementation", "https://cratedb.com/"),
    SoftwareClass("REDIS", "Redis", "database_implementation", "https://redis.io/"),
    SoftwareClass("REDIS", "Valkey", "database_implementation", "https://valkey.io/"),
    SoftwareClass("REDIS", "Dragonfly", "database_implementation", "https://www.dragonflydb.io/"),
    SoftwareClass("REDIS", "Memurai", "database_implementation", "https://www.memurai.com/"),
)


_BY_KEY: dict[tuple[str, str], SoftwareClass] = {}
for item in SOFTWARE_CLASSES:
    _BY_KEY[(item.protocol.upper(), item.label.casefold())] = item
    for alias in item.aliases:
        _BY_KEY[(item.protocol.upper(), alias.casefold())] = item


_TOKEN_ALIASES = {
    ("MYSQL", "mysqlorcompatible"): "",
    ("MYSQL", "mysqlorunmarkedcompatibleserver"): "",
    ("MYSQL", "mysqlcompatible"): "",
    ("PGSQL", "cratedbpostgresqlwireprotocol"): "CrateDB",
    ("REDIS", "redisserverorrediscompatibleimplementationwithoutalternatemarker"): "Redis",
    ("REDIS", "dragonflyrediscompatibleservice"): "Dragonfly",
    ("REDIS", "memurairediscompatibleservice"): "Memurai",
    ("REDIS", "valkeyrediscompatibleservice"): "Valkey",
}


def _compact(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.casefold())


def software_metadata(protocol: str, label: str) -> SoftwareClass | None:
    protocol = protocol.upper()
    raw = (label or "").strip()
    if not raw:
        return None
    direct = _BY_KEY.get((protocol, raw.casefold()))
    if direct:
        return direct
    alias = _TOKEN_ALIASES.get((protocol, _compact(raw)))
    if alias == "":
        return None
    if alias:
        return _BY_KEY.get((protocol, alias.casefold()))
    for (item_protocol, _key), item in _BY_KEY.items():
        if item_protocol != protocol:
            continue
        candidates = (item.label, *item.aliases)
        for candidate in candidates:
            candidate_key = _compact(candidate)
            raw_key = _compact(raw)
            if candidate_key and (candidate_key == raw_key or candidate_key in raw_key):
                return item
    return None


def canonical_software_label(protocol: str, label: str) -> str:
    item = software_metadata(protocol, label)
    return item.label if item else (label or "").strip()


def is_evaluation_software(protocol: str, label: str) -> bool:
    item = software_metadata(protocol, label)
    return bool(item and item.evaluation_eligible)


def software_category(protocol: str, label: str) -> str:
    item = software_metadata(protocol, label)
    return item.category if item else ""


def official_url(protocol: str, label: str) -> str:
    item = software_metadata(protocol, label)
    return item.official_url if item else ""
