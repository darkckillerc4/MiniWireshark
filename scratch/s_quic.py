# ============================================================================
#  5c.  QUIC Initial packets — the site name a browser sends in its first
#       HTTP/3 packet
#
#  A QUIC client's first packet is encrypted with keys anyone can derive from
#  the packet itself (RFC 9001 §5.2: the salt is public and the connection
#  ID is on the wire). It is protection against accidents, not privacy, and
#  every network middlebox may read it. Nothing else of QUIC is readable, and
#  nothing here is "decrypting a connection": once the handshake moves on,
#  real secret keys take over. The name is labelled as read from the first
#  packet; Encrypted Client Hello (ECH) is detected and said out loud.
#
#  Uses the `cryptography` package when present (fast, checks the
#  authentication tag); otherwise a small pure-Python AES-128 + GHASH (also
#  checks the tag). Budgeted so a flood of fake Initials can't eat the CPU.
# ============================================================================
QUIC_V1 = 0x00000001
QUIC_V2 = 0x6b3343cf
QUIC_SALTS = {
    QUIC_V1: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    QUIC_V2: bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"),
}
QUIC_LABELS = {QUIC_V1: (b"quic key", b"quic iv", b"quic hp"),
               QUIC_V2: (b"quicv2 key", b"quicv2 iv", b"quicv2 hp")}
QUIC_INITIAL_TYPE = {QUIC_V1: 0, QUIC_V2: 1}


def _hkdf_extract(salt, ikm):
    import hmac
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand_label(secret, label, length, context=b""):
    import hmac
    full = b"tls13 " + label
    info = struct.pack(">H", length) + bytes([len(full)]) + full + \
        bytes([len(context)]) + context
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(secret, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def quic_initial_keys(dcid, version=QUIC_V1, side="client"):
    """(key, iv, hp) of the Initial packets of one side (RFC 9001 §5.2,
    RFC 9369 §3.3.1 for v2)."""
    initial = _hkdf_extract(QUIC_SALTS[version], dcid)
    secret = _hkdf_expand_label(initial, b"client in" if side == "client"
                                else b"server in", 32)
    lk, li, lh = QUIC_LABELS[version]
    return (_hkdf_expand_label(secret, lk, 16),
            _hkdf_expand_label(secret, li, 12),
            _hkdf_expand_label(secret, lh, 16))


# ---- AES-128 (encrypt direction only: header mask and CTR keystream) -------
def _aes_tables():
    sbox = [0] * 256
    p = q = 1
    while True:                      # generate the S-box (FIPS-197 §5.1.1)
        p = p ^ ((p << 1) & 0xff) ^ (0x1b if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xff
        if q & 0x80:
            q ^= 0x09
        x = q ^ ((q << 1) | (q >> 7)) & 0xff ^ ((q << 2) | (q >> 6)) & 0xff \
            ^ ((q << 3) | (q >> 5)) & 0xff ^ ((q << 4) | (q >> 4)) & 0xff
        sbox[p] = (x ^ 0x63) & 0xff
        if p == 1:
            break
    sbox[0] = 0x63

    def xt(a):
        return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else a << 1
    t0 = []
    for i in range(256):
        s = sbox[i]
        s2 = xt(s)
        s3 = s2 ^ s
        t0.append((s2 << 24) | (s << 16) | (s << 8) | s3)
    t1 = [((v >> 8) | (v << 24)) & 0xffffffff for v in t0]
    t2 = [((v >> 16) | (v << 16)) & 0xffffffff for v in t0]
    t3 = [((v >> 24) | (v << 8)) & 0xffffffff for v in t0]
    return sbox, t0, t1, t2, t3


_AES = None


def _aes_expand(key):
    global _AES
    if _AES is None:
        _AES = _aes_tables()
    sbox = _AES[0]
    w = list(struct.unpack(">4I", key))
    rcon = 1
    for i in range(4, 44):
        t = w[i - 1]
        if i % 4 == 0:
            t = ((t << 8) | (t >> 24)) & 0xffffffff
            t = (sbox[t >> 24] << 24) | (sbox[(t >> 16) & 0xff] << 16) | \
                (sbox[(t >> 8) & 0xff] << 8) | sbox[t & 0xff]
            t ^= rcon << 24
            rcon = ((rcon << 1) ^ 0x1b) & 0xff if rcon & 0x80 else rcon << 1
        w.append(w[i - 4] ^ t)
    return w


def _aes_block(w, block):
    sbox, t0, t1, t2, t3 = _AES
    s0, s1, s2, s3 = struct.unpack(">4I", block)
    s0 ^= w[0]
    s1 ^= w[1]
    s2 ^= w[2]
    s3 ^= w[3]
    k = 4
    for _ in range(9):
        a0 = t0[s0 >> 24] ^ t1[(s1 >> 16) & 0xff] ^ t2[(s2 >> 8) & 0xff] ^ \
            t3[s3 & 0xff] ^ w[k]
        a1 = t0[s1 >> 24] ^ t1[(s2 >> 16) & 0xff] ^ t2[(s3 >> 8) & 0xff] ^ \
            t3[s0 & 0xff] ^ w[k + 1]
        a2 = t0[s2 >> 24] ^ t1[(s3 >> 16) & 0xff] ^ t2[(s0 >> 8) & 0xff] ^ \
            t3[s1 & 0xff] ^ w[k + 2]
        a3 = t0[s3 >> 24] ^ t1[(s0 >> 16) & 0xff] ^ t2[(s1 >> 8) & 0xff] ^ \
            t3[s2 & 0xff] ^ w[k + 3]
        s0, s1, s2, s3 = a0, a1, a2, a3
        k += 4
    o0 = ((sbox[s0 >> 24] << 24) | (sbox[(s1 >> 16) & 0xff] << 16) |
          (sbox[(s2 >> 8) & 0xff] << 8) | sbox[s3 & 0xff]) ^ w[40]
    o1 = ((sbox[s1 >> 24] << 24) | (sbox[(s2 >> 16) & 0xff] << 16) |
          (sbox[(s3 >> 8) & 0xff] << 8) | sbox[s0 & 0xff]) ^ w[41]
    o2 = ((sbox[s2 >> 24] << 24) | (sbox[(s3 >> 16) & 0xff] << 16) |
          (sbox[(s0 >> 8) & 0xff] << 8) | sbox[s1 & 0xff]) ^ w[42]
    o3 = ((sbox[s3 >> 24] << 24) | (sbox[(s0 >> 16) & 0xff] << 16) |
          (sbox[(s1 >> 8) & 0xff] << 8) | sbox[s2 & 0xff]) ^ w[43]
    return struct.pack(">4I", o0, o1, o2, o3)


def aes128_ecb_encrypt(key, block):
    """One AES-128 block (pure Python; used when `cryptography` is not
    installed)."""
    return _aes_block(_aes_expand(key), block)


def _gf128_mul(x, y):
    r = 0xE1000000000000000000000000000000
    z, v = 0, y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        v = (v >> 1) ^ r if v & 1 else v >> 1
    return z


def _ghash(h, aad, ct):
    hx = int.from_bytes(h, "big")
    x = 0
    for data in (aad, ct):
        for i in range(0, len(data), 16):
            blk = data[i:i + 16].ljust(16, b"\x00")
            x = _gf128_mul(x ^ int.from_bytes(blk, "big"), hx)
    x = _gf128_mul(x ^ ((len(aad) * 8) << 64 | len(ct) * 8), hx)
    return x.to_bytes(16, "big")


def _aes_gcm_py(key, nonce, data, aad, decrypt=True):
    """AES-128-GCM with a 96-bit nonce, pure Python. decrypt=True: `data`
    is ciphertext‖tag → plaintext or None on a bad tag."""
    w = _aes_expand(key)
    h = _aes_block(w, b"\x00" * 16)
    j0 = nonce + b"\x00\x00\x00\x01"
    if decrypt:
        if len(data) < 16:
            return None
        ct, tag = data[:-16], data[-16:]
    else:
        ct = None
    src = ct if decrypt else data
    out = bytearray(len(src))
    ctr = 2
    for i in range(0, len(src), 16):
        ks = _aes_block(w, nonce + struct.pack(">I", ctr))
        ctr += 1
        chunk = src[i:i + 16]
        for j, b in enumerate(chunk):
            out[i + j] = b ^ ks[j]
    cipher = ct if decrypt else bytes(out)
    s = _ghash(h, aad, cipher)
    ek = _aes_block(w, j0)
    tag_calc = bytes(a ^ b for a, b in zip(s, ek))
    if decrypt:
        import hmac
        return bytes(out) if hmac.compare_digest(tag_calc, tag) else None
    return bytes(out) + tag_calc


_QUIC_CRYPTO = None


def _quic_crypto():
    """(ecb(key, block), gcm_open(key, nonce, data, aad)) — the fast
    `cryptography` versions when installed, else pure Python."""
    global _QUIC_CRYPTO
    if _QUIC_CRYPTO is not None:
        return _QUIC_CRYPTO
    try:
        from cryptography.hazmat.primitives.ciphers import (Cipher,
                                                            algorithms,
                                                            modes)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.exceptions import InvalidTag

        def ecb(key, block):
            enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
            return enc.update(block) + enc.finalize()

        def gcm_open(key, nonce, data, aad):
            try:
                return AESGCM(key).decrypt(nonce, data, aad)
            except InvalidTag:
                return None
        _QUIC_CRYPTO = (ecb, gcm_open, "cryptography")
    except Exception:                                # noqa: BLE001
        _QUIC_CRYPTO = (aes128_ecb_encrypt,
                        lambda k, n, d, a: _aes_gcm_py(k, n, d, a, True),
                        "pure Python")
    return _QUIC_CRYPTO


def quic_varint(buf, pos):
    if pos >= len(buf):
        raise ValueError("varint past end")
    first = buf[pos]
    n = 1 << (first >> 6)
    if pos + n > len(buf):
        raise ValueError("short varint")
    v = first & 0x3f
    for i in range(1, n):
        v = (v << 8) | buf[pos + i]
    return v, pos + n


def quic_long_header(buf):
    """Parse a long-header packet's clear part. → dict or None."""
    if len(buf) < 7 or not buf[0] & 0x80:
        return None
    version = struct.unpack_from(">I", buf, 1)[0]
    pos = 5
    dl = buf[pos]
    pos += 1
    if dl > 20 or pos + dl >= len(buf):
        return None
    dcid = bytes(buf[pos:pos + dl])
    pos += dl
    sl = buf[pos]
    pos += 1
    if sl > 20 or pos + sl > len(buf):
        return None
    scid = bytes(buf[pos:pos + sl])
    pos += sl
    ptype = (buf[0] >> 4) & 0x03
    out = {"version": version, "dcid": dcid, "scid": scid, "type": ptype,
           "token": b"", "pn_offset": 0, "length": 0, "end": len(buf)}
    if version not in QUIC_SALTS or ptype != QUIC_INITIAL_TYPE[version]:
        return out
    tl, pos = quic_varint(buf, pos)
    out["token"] = bytes(buf[pos:pos + tl])
    pos += tl
    ln, pos = quic_varint(buf, pos)
    out["pn_offset"] = pos
    out["length"] = ln
    out["end"] = min(len(buf), pos + ln)
    out["initial"] = True
    return out


def quic_decrypt_initial(buf, side="client"):
    """Remove header protection and decrypt one Initial packet (the first
    packet in `buf`). → (header dict, plaintext frames) or (hdr, None)."""
    hdr = quic_long_header(buf)
    if not hdr or not hdr.get("initial"):
        return hdr, None
    ecb, gcm_open, _impl = _quic_crypto()
    key, iv, hp = quic_initial_keys(hdr["dcid"], hdr["version"], side)
    pn_off = hdr["pn_offset"]
    if pn_off + 4 + 16 > hdr["end"]:
        return hdr, None
    sample = bytes(buf[pn_off + 4:pn_off + 20])
    mask = ecb(hp, sample)
    first = buf[0] ^ (mask[0] & 0x0f)
    pn_len = (first & 0x03) + 1
    pn_bytes = bytes(b ^ m for b, m in zip(buf[pn_off:pn_off + pn_len],
                                           mask[1:1 + pn_len]))
    pn = int.from_bytes(pn_bytes, "big")
    aad = bytes([first]) + bytes(buf[1:pn_off]) + pn_bytes
    nonce = bytes(a ^ b for a, b in zip(iv, pn.to_bytes(12, "big")))
    payload = bytes(buf[pn_off + pn_len:hdr["end"]])
    plain = gcm_open(key, nonce, payload, aad)
    hdr["pn"] = pn
    return hdr, plain


def quic_crypto_frames(plain):
    """CRYPTO frame pieces [(offset, bytes)] from an Initial packet's
    frames. Raises ValueError on frames an Initial may not carry."""
    out = []
    pos, n = 0, len(plain)
    while pos < n:
        ft = plain[pos]
        if ft == 0x00:                                # PADDING
            pos += 1
        elif ft == 0x01:                              # PING
            pos += 1
        elif ft in (0x02, 0x03):                      # ACK
            pos += 1
            _largest, pos = quic_varint(plain, pos)
            _delay, pos = quic_varint(plain, pos)
            count, pos = quic_varint(plain, pos)
            _first, pos = quic_varint(plain, pos)
            for _ in range(min(count, 256)):
                _g, pos = quic_varint(plain, pos)
                _l, pos = quic_varint(plain, pos)
            if ft == 0x03:
                for _ in range(3):
                    _e, pos = quic_varint(plain, pos)
        elif ft == 0x06:                              # CRYPTO
            off, pos = quic_varint(plain, pos + 1)
            ln, pos = quic_varint(plain, pos)
            if pos + ln > n:
                raise ValueError("short crypto frame")
            out.append((off, plain[pos:pos + ln]))
            pos += ln
        elif ft in (0x1c, 0x1d):                      # CONNECTION_CLOSE
            break
        else:
            raise ValueError(f"frame {ft:#x} not allowed in Initial")
    return out


class QuicInitialReader:
    """Stitches a ClientHello split over several Initial packets (modern
    browsers send post-quantum key shares, so it often needs two) and
    reads the server name. Bounded: 512 connections, 64 KiB each, 5 s;
    at most `budget` packets decrypted per second."""

    MAX_ENTRIES = 512
    MAX_BYTES = 65536
    TTL = 5.0

    def __init__(self, budget=300):
        self.buf = OrderedDict()
        self.done = OrderedDict()
        self.budget = budget
        self._window = [0.0, 0]
        self.decrypted = self.failed = self.skipped = 0

    def _allowed(self, ts):
        w = self._window
        if ts - w[0] >= 1.0 or ts < w[0]:
            w[0], w[1] = ts, 0
        if w[1] >= self.budget:
            self.skipped += 1
            return False
        w[1] += 1
        return True

    def feed(self, key, datagram, ts):
        """→ parse_tls_hello() dict once the ClientHello is complete
        (with "via": "quic"), else None."""
        hdr = quic_long_header(datagram)
        if not hdr or not hdr.get("initial"):
            return None
        ck = (key, hdr["dcid"])
        if ck in self.done:
            return None                       # retransmission: already read
        if not self._allowed(ts):
            return None
        try:
            hdr, plain = quic_decrypt_initial(datagram)
            frames = quic_crypto_frames(plain) if plain else None
        except (ValueError, IndexError, struct.error):
            frames = None
        if frames is None:
            self.failed += 1
            return None
        self.decrypted += 1
        ent = self.buf.get(ck)
        if ent is None:
            ent = self.buf[ck] = {"parts": {}, "ts": ts}
            self._trim(ts)
        for off, data in frames:
            if off < self.MAX_BYTES:
                ent["parts"][off] = data
        hs = self._contiguous(ent["parts"])
        if len(hs) < 4:
            return None
        if hs[0] != 1:                        # not a ClientHello
            self.buf.pop(ck, None)
            return None
        need = 4 + int.from_bytes(hs[1:4], "big")
        if len(hs) < need and len(hs) < self.MAX_BYTES:
            return None
        self.buf.pop(ck, None)
        self.done[ck] = ts
        while len(self.done) > 4 * self.MAX_ENTRIES:
            self.done.popitem(last=False)
        body = hs[:min(need, 16384)]
        rec = b"\x16\x03\x01" + struct.pack(">H", len(body)) + body
        info = parse_tls_hello(rec)
        if not info or info.get("kind") != "client":
            return None
        info["via"] = "quic"
        info["quic_version"] = "v2" if hdr["version"] == QUIC_V2 else "v1"
        return info

    @staticmethod
    def _contiguous(parts):
        out = bytearray()
        while True:
            nxt = None
            for off in parts:
                if off <= len(out) < off + len(parts[off]):
                    nxt = off
                    break
            if nxt is None:
                return bytes(out)
            out += parts[nxt][len(out) - nxt:]

    def _trim(self, ts):
        while len(self.buf) > self.MAX_ENTRIES:
            self.buf.popitem(last=False)
        for k in list(self.buf):
            if ts - self.buf[k]["ts"] > self.TTL:
                self.buf.pop(k, None)
            else:
                break


def quic_build_initial(dcid, scid, crypto, pn=0, version=QUIC_V1,
                       crypto_offset=0, pad_to=1200, frames=None):
    """Build a client Initial packet (tests, demo data and the self-test).
    `crypto` = ClientHello bytes (no record header) placed at
    `crypto_offset`; `frames` = raw frame bytes to use instead."""
    if frames is None:
        frames = b"\x06" + _quic_varint_enc(crypto_offset) + \
            _quic_varint_enc(len(crypto)) + crypto
    key, iv, hp = quic_initial_keys(dcid, version)
    pn_len = 4
    first = 0xc0 | (QUIC_INITIAL_TYPE[version] << 4) | (pn_len - 1)
    head = bytes([first]) + struct.pack(">I", version) + bytes([len(dcid)]) \
        + dcid + bytes([len(scid)]) + scid + _quic_varint_enc(0)
    overhead = len(head) + 2 + pn_len + 16
    if overhead + len(frames) < pad_to:
        frames = frames + b"\x00" * (pad_to - overhead - len(frames))
    length = pn_len + len(frames) + 16
    head += struct.pack(">H", 0x4000 | length)
    pn_bytes = pn.to_bytes(pn_len, "big")
    aad = head + pn_bytes
    nonce = bytes(a ^ b for a, b in zip(iv, pn.to_bytes(12, "big")))
    sealed = _aes_gcm_py(key, nonce, frames, aad, decrypt=False)
    pkt = bytearray(aad + sealed)
    pn_off = len(head)
    ecb = _quic_crypto()[0]
    mask = ecb(hp, bytes(pkt[pn_off + 4:pn_off + 20]))
    pkt[0] ^= mask[0] & 0x0f
    for i in range(pn_len):
        pkt[pn_off + i] ^= mask[1 + i]
    return bytes(pkt)


def _quic_varint_enc(v):
    if v < 0x40:
        return bytes([v])
    if v < 0x4000:
        return struct.pack(">H", 0x4000 | v)
    if v < 0x40000000:
        return struct.pack(">I", 0x80000000 | v)
    return struct.pack(">Q", 0xC000000000000000 | v)


def tls_client_hello(sni, alpn=("h3",), ech=False, pad_ext=0):
    """A minimal TLS 1.3 ClientHello handshake message (no record header)
    for tests and demo data."""
    def ext(t, body):
        return struct.pack(">HH", t, len(body)) + body
    name = sni.encode()
    exts = ext(0, struct.pack(">HBH", len(name) + 3, 0, len(name)) + name)
    al = b"".join(bytes([len(a)]) + a.encode() for a in alpn)
    exts += ext(16, struct.pack(">H", len(al)) + al)
    exts += ext(43, b"\x02\x03\x04")
    if ech:
        exts += ext(0xfe0d, b"\x00" * 32)
    if pad_ext:
        exts += ext(21, b"\x00" * pad_ext)
    body = b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x02\x13\x01" + \
        b"\x01\x00" + struct.pack(">H", len(exts)) + exts
    return b"\x01" + len(body).to_bytes(3, "big") + body
