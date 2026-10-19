def runtime_handoff(argv=None, environ=None, execute=True, suitable=None,
                    timeout=HANDSHAKE_TIMEOUT):
    """Decide whether to start the app inside the managed Python. Returns
    the command it ran (or would run), or None to continue in this Python.

    V5 rules: never when this Python can run the app, unless you chose the
    managed Python in the Runtime Manager; never in Safe Mode; and the
    child must report its window within the handshake time, or this
    process stays and explains why."""
    environ = os.environ if environ is None else environ
    argv = list(sys.argv[1:] if argv is None else argv)
    if environ.get("MW_STAGE") == "app" or MW_STAGE == "app" or \
            NO_RUNTIME_FLAG in argv or \
            environ.get("MINIWIRESHARK_NO_RUNTIME") or SAFE_MODE:
        return None
    state = runtime_state_read()
    env = runtime_env(state)
    if not runtime_healthy(env):
        return None
    if _same_interpreter(env["python"], sys.executable):
        return None
    ok, _why = suitable if suitable is not None else system_python_suitable()
    if ok and state.get("prefer", "auto") != "managed":
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
    ready = os.path.join(BOOT_DIR, f"ready-{os.getpid()}-"
                                   f"{uuid.uuid4().hex[:8]}")
    cmd = [env["python"], SCRIPT_PATH] + argv + [STAGE_ARG,
                                                 READY_ARG + ready]
    if not execute:
        return cmd[:len(cmd) - 2]
    child_env = dict(environ)
    child_env["MW_STAGE"] = "app"
    child_env["MW_READY_FILE"] = ready
    log_path = _child_log_path()
    boot_step("hand-off", True, f"starting the managed Python "
                                f"{env.get('version', '?')}")
    try:
        os.makedirs(BOOT_DIR, exist_ok=True)
        logf = open(log_path, "wb")
    except OSError:
        logf = subprocess.DEVNULL
    try:
        flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) \
            if IS_WINDOWS else 0
        proc = subprocess.Popen(cmd, env=child_env, creationflags=flags,
                                close_fds=True, stdout=logf,
                                stderr=subprocess.STDOUT)
    except OSError as e:
        _handoff_failed(env, f"could not start it: {e}", log_path)
        return None
    finally:
        if logf is not subprocess.DEVNULL:
            with contextlib.suppress(OSError):
                logf.close()
    result, rc = wait_for_handshake(proc, ready, timeout=timeout)
    if result == "ready":
        with contextlib.suppress(OSError):
            os.remove(ready)
        boot_step("hand-off", True, "the managed Python's window is up")
        if BOOT is not None:
            BOOT.mark(outcome="handed_off", reached_window=True)
        sys.exit(0)
    if result == "timeout" and proc.poll() is None:
        with contextlib.suppress(OSError):
            proc.terminate()
        with contextlib.suppress(subprocess.SubprocessError, OSError):
            proc.wait(5)
        with contextlib.suppress(OSError):
            proc.kill()
    why = (f"its window did not appear within {int(timeout)} s"
           if result == "timeout" else f"it stopped with code {rc} before "
                                       f"opening its window")
    _handoff_failed(env, why, log_path)
    return None


def _handoff_failed(env, why, log_path):
    """Remember a failed hand-off so it is not retried automatically, and
    tell this start what happened."""
    tail = _tail(log_path, 600).strip()
    state = runtime_state_read()
    cur = state.get("current")
    envs = state.get("envs") or {}
    if cur in envs:
        envs[cur]["handshake_failed"] = time.time()
        envs[cur]["handshake_error"] = why
    state["pending_starts"] = 0
    state["last_error"] = (f"The managed Python {env.get('version', '')} "
                           f"could not start: {why}. MiniWireshark is using "
                           f"this Python instead. Log: {log_path}")
    with contextlib.suppress(OSError):
        runtime_state_write(state)
    HANDOFF_NOTE[0] = state["last_error"]
    boot_step("hand-off", False, why + (f" | {tail[-300:]}" if tail else ""))
    LOG.warning("hand-off failed: %s", why)
