from datetime import datetime, timedelta
import ipaddress

import logging

loader = logging.getLogger('TLS CA')

def check_expired_cert(cert_pem):
    from cryptography import x509
    cert = x509.load_pem_x509_certificate(cert_pem)
    valid_timedelta = cert_data.not_valid_after_utc - datetime.utcnow()
    if valid_timedelta < timedelta(days=0, seconds=0):
        logging.error('TLS Cert expires in %s hours', valid_timedelta.seconds//3600)
        return True
    if valid_timedelta < timedelta(days=1):
        logging.error('TLS Cert expires in %s hours', valid_timedelta.seconds//3600)
        return True
    if valid_timedelta < timedelta(days=30):
        logging.warning('TLS Cert expires in %s days', valid_timedelta.days)
        return True
    return False


def load_cert(cert_pem):
    from cryptography import x509
    return x509.load_pem_x509_certificate(cert_pem)
    

def load_key(key_pem):
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    try:
        return load_pem_private_key(key_pem)
    except:
        logger.error('Key corrupted')

def generate_selfsigned_ca(hostname, ip_addresses=None, key=None):
    """Generates self signed certificate for a hostname, and optional IP addresses."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    # Generate our key
    if key is None:
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )

    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname+" CA")
    ])

    # path_len=0 means this cert can only sign itself, not other certs.
    basic_contraints = x509.BasicConstraints(ca=True, path_length=1)
    now = datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1000)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=25*365))
        .add_extension(basic_contraints, False)
        .sign(key, hashes.SHA256(), default_backend())
    )
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return cert_pem, key_pem, cert, key




def generate_selfsigned_cert(hostname, ip_addresses=None, ca=None, cakey=None, key=None):
    """Generates self signed certificate for a hostname, and optional IP addresses."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    # Generate our key
    if key is None:
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )

    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname)
    ])

    # best practice seem to be to include the hostname in the SAN, which *SHOULD* mean COMMON_NAME is ignored.
    alt_names = [x509.DNSName(hostname)]

    # allow addressing by IP, for when you don't have real DNS (common in most testing scenarios
    if ip_addresses:
        for addr in ip_addresses:
            # openssl wants DNSnames for ips...
            alt_names.append(x509.DNSName(addr))
            # ... whereas golang's crypto/tls is stricter, and needs IPAddresses
            # note: older versions of cryptography do not understand ip_address objects
            alt_names.append(x509.IPAddress(ipaddress.ip_address(addr)))

    san = x509.SubjectAlternativeName(alt_names)

    # path_len=0 means this cert can only sign itself, not other certs.
    basic_contraints = x509.BasicConstraints(ca=False, path_length=None)
    now = datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1001)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1*365))
        .add_extension(basic_contraints, False)
        .add_extension(san, False)
        # .sign(key, hashes.SHA256(), default_backend())
        .sign(cakey, hashes.SHA256(), default_backend())
    )
    # cert_pem = ca.public_bytes(encoding=serialization.Encoding.PEM)
    # cert_pem += b'\n'
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return cert_pem, key_pem
