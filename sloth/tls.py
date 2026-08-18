"""TLS for the built-in server.

Sloth carries engagement data and a login, so serving it in the clear — even
on a LAN a client shares — leaks the session cookie and every scan result to
anyone sniffing the segment. HTTPS closes that.

A self-signed certificate is generated on first use when none is supplied, so
`--tls` works with no setup. It is self-signed, so a browser warns once and you
accept it; that is expected for a tool you run yourself. Point SLOTH_TLS_CERT
and SLOTH_TLS_KEY at a real pair (an internal CA, mkcert, Let's Encrypt) to
replace it and lose the warning.
"""
import datetime
import ipaddress
import os
import ssl

from .config import TLS_CERT, TLS_KEY


def _self_signed(cert_path, key_path, host):
    """Writes a fresh self-signed cert/key pair. Needs `cryptography`."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Cover the obvious names so the cert matches however the tool is reached:
    # loopback, the configured bind address, and the machine's hostname.
    names = ["localhost"]
    ips = ["127.0.0.1", "::1"]
    if host and host not in ("127.0.0.1", "0.0.0.0", "::"):
        (ips if _is_ip(host) else names).append(host)
    try:
        hostname = os.uname().nodename
        if hostname and hostname not in names:
            names.append(hostname)
    except (AttributeError, OSError):
        pass

    san = [x509.DNSName(n) for n in dict.fromkeys(names)]
    for ip in dict.fromkeys(ips):
        try:
            san.append(x509.IPAddress(ipaddress.ip_address(ip)))
        except ValueError:
            pass

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Sloth")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    os.makedirs(os.path.dirname(os.path.abspath(cert_path)), exist_ok=True)
    with open(cert_path, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    # The key is a secret: readable only by the owner, written before use.
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def ssl_context(host=None):
    """Returns an SSLContext for app.run, generating a cert if needed.

    Raises RuntimeError with a plain sentence when a supplied cert cannot be
    loaded, or when generation is needed but `cryptography` is absent — a
    traceback out of app startup helps no one.
    """
    cert, key = TLS_CERT, TLS_KEY
    have_both = os.path.isfile(cert) and os.path.isfile(key)
    generated = False

    if not have_both:
        # A half-supplied pair (one path exists, the other does not) is a
        # configuration mistake, not a reason to overwrite with a self-signed one.
        if os.path.isfile(cert) != os.path.isfile(key):
            missing = key if os.path.isfile(cert) else cert
            raise RuntimeError(
                f"TLS is on but {missing} is missing. Supply both "
                f"SLOTH_TLS_CERT and SLOTH_TLS_KEY, or neither to auto-generate.")
        try:
            _self_signed(cert, key, host)
            generated = True
        except ImportError as exc:
            raise RuntimeError(
                "TLS needs a certificate. Install the 'cryptography' package to "
                "auto-generate a self-signed one, or point SLOTH_TLS_CERT and "
                "SLOTH_TLS_KEY at your own pair.") from exc

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(cert, key)
    except (ssl.SSLError, OSError) as exc:
        raise RuntimeError(f"Could not load the TLS certificate ({cert}): {exc}") from exc
    return context, cert, generated
