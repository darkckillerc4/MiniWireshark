# ============================================================================
#  1a.  Layer 1 — wide-entry launcher and runtime hand-off
#
#  This part runs on whatever Python started the file (3.8 or newer) and
#  uses only the standard library. If MiniWireshark has a healthy private
#  Python (installed once, with your consent, into the data folder), the
#  script re-launches itself with it — a normal start does nothing else:
#  no downloads, no installs, no changes to the system. Loops are
#  impossible: the child is marked with MW_STAGE=app, and two failed starts
#  in a row switch back to the previous runtime (or to this Python).
#  The system Python, PATH and file associations are never touched.
# ============================================================================
RUNTIME_STATE_VERSION = 1
MW_STAGE = os.environ.get("MW_STAGE", "")
NO_RUNTIME_FLAG = "--no-runtime"
RUNTIME_DIR = os.path.join(PATHS.data, "runtime")
RUNTIME_STATE = os.path.join(RUNTIME_DIR, "state.json")


def _state_checksum(state):
    body = {k: v for k, v in state.items() if k != "checksum"}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"),
                     default=str).encode()
    return hashlib.sha256(raw).hexdigest()


def runtime_state_read():
    """The runtime state, or {} when missing, unreadable or tampered."""
    st = read_json(RUNTIME_STATE, None)
    if not isinstance(st, dict):
        return {}
    if st.get("checksum") != _state_checksum(st):
        return {}
    return st


def runtime_state_write(state):
    state = dict(state)
    state["version"] = RUNTIME_STATE_VERSION
    state["checksum"] = _state_checksum(state)
    os.makedirs(RUNTIME_DIR, exist_ok=True)
    atomic_write_json(RUNTIME_STATE, state)
    return state


def runtime_env(state, env_id=None):
    env_id = env_id or state.get("current")
    env = (state.get("envs") or {}).get(env_id) if env_id else None
    return env if isinstance(env, dict) else None


def runtime_healthy(env):
    """Cheap check (no subprocess): the interpreter file exists and the
    last self-test inside it passed."""
    if not env:
        return False
    exe = env.get("python", "")
    return bool(exe and os.path.isfile(exe) and env.get("selftest_ok"))


def _same_interpreter(a, b):
    try:
        return os.path.normcase(os.path.realpath(a)) == \
            os.path.normcase(os.path.realpath(b))
    except (OSError, ValueError):
        return False


def runtime_handoff(argv=None, environ=None, execute=True):
    """Decide whether to re-launch inside the private runtime. Returns the
    command it ran (or would run), or None to continue in this Python."""
    environ = os.environ if environ is None else environ
    argv = list(sys.argv[1:] if argv is None else argv)
    if environ.get("MW_STAGE") == "app" or NO_RUNTIME_FLAG in argv or \
            environ.get("MINIWIRESHARK_NO_RUNTIME"):
        return None
    state = runtime_state_read()
    env = runtime_env(state)
    if not runtime_healthy(env):
        return None
    if _same_interpreter(env["python"], sys.executable):
        return None
    if int(state.get("pending_starts", 0)) >= 2:
        # the last two starts inside this runtime never confirmed: roll back
        prev = runtime_env(state, state.get("previous"))
        state["rolled_back"] = {"from": state.get("current"),
                                "at": time.time()}
        if runtime_healthy(prev):
            state["current"], state["previous"] = state.get("previous"), \
                state.get("current")
            env = prev
        else:
            state["current"] = ""
            state["pending_starts"] = 0
            with contextlib.suppress(OSError):
                runtime_state_write(state)
            return None
        state["pending_starts"] = 0
    state["pending_starts"] = int(state.get("pending_starts", 0)) + 1
    with contextlib.suppress(OSError):
        runtime_state_write(state)
    cmd = [env["python"], SCRIPT_PATH] + argv
    if not execute:
        return cmd
    child_env = dict(environ)
    child_env["MW_STAGE"] = "app"
    try:
        if IS_WINDOWS:
            flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            subprocess.Popen(cmd, env=child_env, creationflags=flags,
                             close_fds=True)
            sys.exit(0)
        os.execve(cmd[0], cmd, child_env)
    except OSError as e:
        state = runtime_state_read()
        state["pending_starts"] = max(0, int(state.get("pending_starts",
                                                       1)) - 1)
        state["last_error"] = f"could not start the private Python: {e}"
        with contextlib.suppress(OSError):
            runtime_state_write(state)
        return None
    return cmd


def runtime_confirm_started():
    """Called by the app once it has been up for a while: this runtime
    works, so clear the failed-start counter."""
    if MW_STAGE != "app":
        return False
    state = runtime_state_read()
    if not state or not state.get("pending_starts"):
        return False
    state["pending_starts"] = 0
    env = runtime_env(state)
    if env is not None:
        env["last_ok_start"] = time.time()
    with contextlib.suppress(OSError):
        runtime_state_write(state)
    return True


def needs_elevation():
    """Least privilege: Windows with Npcap installed in its default mode
    lets ordinary users capture, so the app starts unelevated there and
    only the driver installation asks for administrator rights."""
    if is_admin():
        return False
    if IS_WINDOWS:
        if not _npcap_present_early():
            return True
        return _npcap_admin_only()
    return True


def _npcap_present_early():
    sd = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                      "System32")
    return any(os.path.exists(p) for p in
               (os.path.join(sd, "Npcap", "wpcap.dll"),
                os.path.join(sd, "wpcap.dll")))


def _npcap_admin_only():
    if not IS_WINDOWS:
        return False
    try:
        import winreg
        for path in (r"SYSTEM\CurrentControlSet\Services\npcap\Parameters",
                     r"SOFTWARE\WOW6432Node\Npcap", r"SOFTWARE\Npcap"):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as k:
                    v, _t = winreg.QueryValueEx(k, "AdminOnly")
                    return bool(v)
            except OSError:
                continue
    except ImportError:
        pass
    return False


