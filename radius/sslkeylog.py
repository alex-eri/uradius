import ssl
import _sslkeylog

OPENSSL111 = ssl.OPENSSL_VERSION_INFO[:3] >= (1, 1, 1)


def export_keying_material(sock, size, label):
    if not OPENSSL111:
        raise NotImplementedError("Method inplemented in OpenSSL 1.1.1")

    if sock is None:
        raise TypeError(
            "export_keying_material() argument must be ssl.SSLSocket or ssl.SSLObject, not None")

    # Some Python versions implement SSLSocket using SSLObject so we need to dereference twice
    sock = getattr(sock, '_sslobj', sock)
    sock = getattr(sock, '_sslobj', sock)
    if sock is None:
        return None

    return _sslkeylog.export_keying_material(sock, size, label)


def get_server_random(sock):
    """Get the server random from an :class:`ssl.SSLSocket` or :class:`ssl.SSLObject`."""
    if sock is None:
        raise TypeError(
            "get_server_random() argument must be ssl.SSLSocket or ssl.SSLObject, not None")

    # Some Python versions implement SSLSocket using SSLObject so we need to dereference twice
    sock = getattr(sock, '_sslobj', sock)
    sock = getattr(sock, '_sslobj', sock)
    if sock is None:
        return None

    return _sslkeylog.get_server_random(sock)


def get_client_random(sock):
    """
    Get the client random from an :class:`ssl.SSLSocket` or :class:`ssl.SSLObject`.
    .. note:: Does not work with TLS v1.3+ sockets.
    """
    if sock is None:
        raise TypeError(
            "get_client_random() argument must be ssl.SSLSocket or ssl.SSLObject, not None")

    # Some Python versions implement SSLSocket using SSLObject so we need to dereference twice
    sock = getattr(sock, '_sslobj', sock)
    sock = getattr(sock, '_sslobj', sock)
    if sock is None:
        return None

    return _sslkeylog.get_client_random(sock)