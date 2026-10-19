# ============================================================================
#  21b.  Signed updates and data packs (Ed25519)
#
#  An update is installed only when its manifest is signed by one of the
#  release keys below, its SHA-256 and size match, and it is newer than
#  this version (no downgrades). With no release key configured, updates
#  are check-only: you are told a new version exists, nothing is installed.
#  Verification uses `cryptography` when present, else a small pure-Python
#  Ed25519 (RFC 8032), checked against the RFC's own test vectors.
# ============================================================================
RELEASE_KEYS = {
    # "key-id": "64 hex chars of an Ed25519 public key" — added by the
    # person who publishes releases (see --make-release-key). Two keys may
    # be listed at once so a key can be rotated without breaking updates.
}
MANIFEST_NAME = "miniwireshark.manifest.json"

_ED_P = 2 ** 255 - 19
_ED_Q = 2 ** 252 + 27742317777372353535851937790883648493
_ED_D = -121665 * pow(121666, _ED_P - 2, _ED_P) % _ED_P
_ED_I = pow(2, (_ED_P - 1) // 4, _ED_P)


def _ed_add(P, Q):
    p, d = _ED_P, _ED_D
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % p
    C = 2 * P[3] * Q[3] * d % p
    D = 2 * P[2] * Q[2] % p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % p, G * H % p, F * G % p, E * H % p)


def _ed_mul(s, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _ed_add(Q, P)
        P = _ed_add(P, P)
        s >>= 1
    return Q


def _ed_recover_x(y, sign):
    p = _ED_P
    if y >= p:
        return None
    x2 = (y * y - 1) * pow(_ED_D * y * y + 1, p - 2, p) % p
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p:
        x = x * _ED_I % p
    if (x * x - x2) % p:
        return None
    if (x & 1) != sign:
        x = p - x
    return x


_ED_GY = 4 * pow(5, _ED_P - 2, _ED_P) % _ED_P
_ED_GX = _ed_recover_x(_ED_GY, 0)
_ED_G = (_ED_GX, _ED_GY, 1, _ED_GX * _ED_GY % _ED_P)


def _ed_decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _ed_recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _ED_P)


def _ed_compress(P):
    zi = pow(P[2], _ED_P - 2, _ED_P)
    x, y = P[0] * zi % _ED_P, P[1] * zi % _ED_P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _ed_equal(P, Q):
    p = _ED_P
    return (P[0] * Q[2] - Q[0] * P[2]) % p == 0 and \
        (P[1] * Q[2] - Q[1] * P[2]) % p == 0


def ed25519_public_key(secret):
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return _ed_compress(_ed_mul(a, _ED_G))


def ed25519_sign(secret, msg):
    """Release tooling only (the app itself never signs anything)."""
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    A = _ed_compress(_ed_mul(a, _ED_G))
    r = int.from_bytes(hashlib.sha512(h[32:] + msg).digest(), "little") \
        % _ED_Q
    Rs = _ed_compress(_ed_mul(r, _ED_G))
    k = int.from_bytes(hashlib.sha512(Rs + A + msg).digest(), "little") \
        % _ED_Q
    return Rs + ((r + k * a) % _ED_Q).to_bytes(32, "little")


def _ed25519_verify_py(public, msg, sig):
    if len(public) != 32 or len(sig) != 64:
        return False
    A = _ed_decompress(public)
    R = _ed_decompress(sig[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _ED_Q:
        return False
    k = int.from_bytes(hashlib.sha512(sig[:32] + public + msg).digest(),
                       "little") % _ED_Q
    return _ed_equal(_ed_mul(s, _ED_G), _ed_add(R, _ed_mul(k, A)))


def ed25519_verify(public, msg, sig):
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import \
            Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
    except Exception:                                # noqa: BLE001
        return _ed25519_verify_py(public, msg, sig)
    try:
        Ed25519PublicKey.from_public_bytes(bytes(public)).verify(bytes(sig),
                                                                msg)
        return True
    except (InvalidSignature, ValueError):
        return False


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode()


def sign_manifest(body, keys):
    """body: dict without "signatures"; keys: {key_id: 32-byte secret}."""
    msg = _canonical(body)
    out = dict(body)
    out["signatures"] = [{"key": kid, "sig": ed25519_sign(sec, msg).hex()}
                         for kid, sec in keys.items()]
    return out


class UpdateRefused(ValueError):
    pass


def verify_manifest(manifest, trusted=None, kind="release"):
    """→ the manifest body when a trusted key signed it, else raises
    UpdateRefused with a plain-English reason."""
    trusted = RELEASE_KEYS if trusted is None else trusted
    if not trusted:
        raise UpdateRefused("No release key is configured, so updates are "
                            "check-only (nothing is installed "
                            "automatically).")
    if not isinstance(manifest, dict) or manifest.get("kind", "release") \
            != kind:
        raise UpdateRefused("Not a MiniWireshark manifest of this kind.")
    body = {k: v for k, v in manifest.items() if k != "signatures"}
    msg = _canonical(body)
    for s in manifest.get("signatures") or []:
        pk = trusted.get(s.get("key", ""))
        if not pk:
            continue
        with contextlib.suppress(ValueError, TypeError):
            if ed25519_verify(bytes.fromhex(pk), msg, bytes.fromhex(
                    s.get("sig", ""))):
                return body
    raise UpdateRefused("The release isn't signed by a key this "
                        "MiniWireshark trusts — it was NOT installed.")


def check_release(manifest, data, current=SCRIPT_VERSION, trusted=None):
    """All checks before an update is installed."""
    body = verify_manifest(manifest, trusted)
    if _version_tuple(body.get("version", "")) <= _version_tuple(current):
        raise UpdateRefused(f"The release ({body.get('version')}) isn't "
                            f"newer than this one ({current}) — downgrades "
                            f"are refused.")
    if len(data) != int(body.get("size", -1)):
        raise UpdateRefused("The download is incomplete or the wrong size.")
    if hashlib.sha256(data).hexdigest() != body.get("sha256"):
        raise UpdateRefused("The download doesn't match the signed "
                            "fingerprint.")
    return body


def make_release_manifest(script_bytes, version, keys, notes=""):
    return sign_manifest({"kind": "release", "app": APP_NAME,
                          "version": version,
                          "sha256": hashlib.sha256(script_bytes).hexdigest(),
                          "size": len(script_bytes), "notes": notes,
                          "made": time.strftime("%Y-%m-%d")}, keys)


# ---- data packs: signed updates of the reference lists -----------------------
DATA_PACK_TARGETS = {"services": "PORT_SERVICES", "doh": "DOH_HOSTS"}


def apply_data_pack(pack, trusted=None):
    """Install a signed data pack (port→service names, encrypted-DNS
    hosts). → number of entries added."""
    body = verify_manifest(pack, trusted, kind="datapack")
    target = DATA_PACK_TARGETS.get(body.get("pack"))
    if target is None:
        raise UpdateRefused(f"Unknown data pack “{body.get('pack')}”.")
    data = body.get("data") or {}
    if not isinstance(data, dict) or len(data) > 50000:
        raise UpdateRefused("The data pack is malformed.")
    table = globals()[target]
    n = 0
    for k, v in data.items():
        key = int(k) if target == "PORT_SERVICES" else str(k).lower()
        val = sanitize_text(str(v), 80)
        if table.get(key) != val:
            table[key] = val
            n += 1
    return n


def release_check(path=None):
    """Release checklist (developers): prints what to verify and the
    file's fingerprint. Exit code 0 only when every automatic check
    passes."""
    path = path or SCRIPT_PATH
    with open(path, "rb") as f:
        data = f.read()
    text = data.decode("utf-8")
    checks = []
    try:
        import ast
        ast.parse(text, feature_version=(3, 8))
        checks.append(("Python 3.8 grammar", True, ""))
    except SyntaxError as e:
        checks.append(("Python 3.8 grammar", False, str(e)))
    m = re.search(r'^SCRIPT_VERSION = "([^"]+)"', text, re.M)
    checks.append(("Version string", bool(m), m.group(1) if m else ""))
    checks.append(("Release keys listed", bool(RELEASE_KEYS),
                   ", ".join(RELEASE_KEYS) or "none — updates check-only"))
    checks.append(("Runtime lock fingerprint", True, lock_fingerprint()))
    checks.append(("No debugger left in", "breakpoint()" not in text.replace(
        '"breakpoint()"', ""), ""))
    print(f"MiniWireshark release check — {os.path.basename(path)}")
    for name, ok, detail in checks:
        print(f"  [{'OK' if ok else '!!'}] {name}" + (f": {detail}"
                                                      if detail else ""))
    print(f"  sha256 {hashlib.sha256(data).hexdigest()}  size {len(data)}")
    print("  Manual: run --self-test and --gui-test on Windows, macOS and "
          "Linux; sign with --sign-release; attach the .py and "
          f"{MANIFEST_NAME} to the release.")
    return 0 if all(ok for name, ok, _d in checks
                    if name != "Release keys listed") else 1


