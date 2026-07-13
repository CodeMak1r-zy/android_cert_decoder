from __future__ import annotations

import struct
import warnings
from dataclasses import dataclass
from datetime import datetime, timezone

import jks
from jks.bks import KEY_TYPE_PRIVATE
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, pkcs12


@dataclass
class CertInfo:
    alias: str
    sha1: str
    sha256: str
    md5: str
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    public_key_pem: str


class KeystoreError(Exception):
    pass


def _format_fingerprint(digest: bytes) -> str:
    return ":".join(f"{b:02X}" for b in digest)


def _dn_string(name: x509.Name) -> str:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        return ", ".join(f"{attr.oid._name}={attr.value}" for attr in name)


def _public_key_pem(cert: x509.Certificate) -> str:
    # Equivalent to: openssl x509 -pubkey -noout
    return cert.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("ascii")


def _cert_info(alias: str, cert: x509.Certificate) -> CertInfo:
    return CertInfo(
        alias=alias,
        sha1=_format_fingerprint(cert.fingerprint(hashes.SHA1())),
        sha256=_format_fingerprint(cert.fingerprint(hashes.SHA256())),
        md5=_format_fingerprint(cert.fingerprint(hashes.MD5())),
        subject=_dn_string(cert.subject),
        issuer=_dn_string(cert.issuer),
        not_before=cert.not_valid_before_utc.replace(tzinfo=timezone.utc),
        not_after=cert.not_valid_after_utc.replace(tzinfo=timezone.utc),
        public_key_pem=_public_key_pem(cert),
    )


def _append_cert(results: list[CertInfo], seen: set[str], alias: str, cert: x509.Certificate) -> None:
    key = cert.fingerprint(hashes.SHA256()).hex()
    if key in seen:
        return
    seen.add(key)
    results.append(_cert_info(alias, cert))


def _is_jks(data: bytes) -> bool:
    magic = data[:4]
    return magic == jks.MAGIC_NUMBER_JKS or magic == jks.MAGIC_NUMBER_JCEKS


def _is_pkcs12(data: bytes) -> bool:
    return len(data) > 4 and data[0] == 0x30


def _is_bks_version(data: bytes) -> bool:
    if len(data) < 4:
        return False
    version = struct.unpack(">L", data[:4])[0]
    return version in (1, 2)


def _load_keystore(data: bytes, storepass: str):
    if _is_jks(data):
        return jks.KeyStore.loads(data, storepass, try_decrypt_keys=False)

    if _is_pkcs12(data):
        return None

    if _is_bks_version(data):
        try:
            return jks.BksKeyStore.loads(data, storepass, try_decrypt_keys=True)
        except jks.util.KeystoreSignatureException:
            raise
        except jks.util.BadKeystoreFormatException:
            pass

    try:
        return jks.UberKeyStore.loads(data, storepass, try_decrypt_keys=True)
    except jks.util.KeystoreSignatureException:
        raise
    except jks.util.DecryptionFailureException:
        raise KeystoreError("storepass 不正确") from None
    except jks.util.BadKeystoreFormatException:
        pass

    if _is_pkcs12(data):
        return None

    raise KeystoreError("无法识别的 keystore 格式（支持 JKS / PKCS12 / BKS）")


def _collect_jks_certs(keystore: jks.KeyStore, results: list[CertInfo], seen: set[str]) -> None:
    for alias, entry in keystore.private_keys.items():
        if not entry.cert_chain:
            continue
        cert = x509.load_der_x509_certificate(entry.cert_chain[0][1])
        _append_cert(results, seen, alias, cert)

    for alias, entry in keystore.certs.items():
        cert = x509.load_der_x509_certificate(entry.cert)
        _append_cert(results, seen, alias, cert)


def _collect_bks_certs(keystore, results: list[CertInfo], seen: set[str]) -> None:
    for alias, entry in keystore.certs.items():
        cert = x509.load_der_x509_certificate(entry.cert)
        _append_cert(results, seen, alias, cert)

    for alias, entry in keystore.plain_keys.items():
        if entry.type != KEY_TYPE_PRIVATE or not entry.cert_chain:
            continue
        cert = x509.load_der_x509_certificate(entry.cert_chain[0][1])
        _append_cert(results, seen, alias, cert)

    for alias, entry in keystore.sealed_keys.items():
        if not entry.is_decrypted():
            continue
        if not entry.cert_chain:
            continue
        cert = x509.load_der_x509_certificate(entry.cert_chain[0][1])
        _append_cert(results, seen, alias, cert)


def _parse_pkcs12(data: bytes, storepass: str, results: list[CertInfo], seen: set[str]) -> None:
    password = storepass.encode("utf-8")
    try:
        _key, cert, additional = pkcs12.load_key_and_certificates(data, password)
    except ValueError as exc:
        raise KeystoreError("storepass 不正确") from exc

    if cert is not None:
        _append_cert(results, seen, "1", cert)
    for index, chain_cert in enumerate(additional or (), start=2):
        _append_cert(results, seen, str(index), chain_cert)


def parse_keystore(file_path: str, storepass: str) -> list[CertInfo]:
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except OSError as exc:
        raise KeystoreError(f"无法读取文件: {exc}") from exc

    if not storepass:
        raise KeystoreError("请输入 storepass")

    results: list[CertInfo] = []
    seen: set[str] = set()

    try:
        if _is_pkcs12(data):
            _parse_pkcs12(data, storepass, results, seen)
        else:
            keystore = _load_keystore(data, storepass)
            if isinstance(keystore, jks.KeyStore):
                _collect_jks_certs(keystore, results, seen)
            else:
                _collect_bks_certs(keystore, results, seen)
    except jks.util.KeystoreSignatureException as exc:
        raise KeystoreError("storepass 不正确") from exc
    except jks.util.DecryptionFailureException as exc:
        raise KeystoreError("storepass 不正确") from exc
    except KeystoreError:
        raise
    except Exception as exc:
        raise KeystoreError(f"无法解析 keystore 文件: {exc}") from exc

    if not results:
        raise KeystoreError("keystore 中未找到证书")

    return results
