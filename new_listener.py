# remote_jump.py
# IDA Pro 7.6 (IDAPython).
# TCP listener for AsmRunner packets:
#   A <1 byte addr_size> <addr bytes little-endian>
#   I <uint32 len little-endian> <idc text bytes utf-8>
#
# Usage:
#   import remote_jump
#   remote_jump.start_listener(host='127.0.0.1', port=27310)
#   remote_jump.stop_listener()

import socket
import struct
import threading
import time

import ida_kernwin
import idc

_listener_thread = None
_stop_event = None


def _log(msg):
    try:
        ida_kernwin.msg(msg)
    except Exception:
        pass


def _safe_jumpto(addr):
    try:
        flags = getattr(ida_kernwin, "MFF_WRITE", 0)
        ida_kernwin.execute_sync(lambda: ida_kernwin.jumpto(addr), flags)
    except Exception:
        try:
            ida_kernwin.jumpto(addr)
        except Exception as e:
            _log("[remote_jump] jump failed: %s\n" % str(e))


def _split_idc_statements(text):
    stmts = []
    buf = []
    in_quotes = False
    escape = False

    for ch in text:
        if in_quotes:
            buf.append(ch)
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == '"':
                in_quotes = False
            continue

        if ch == '"':
            in_quotes = True
            buf.append(ch)
            continue

        if ch == ';':
            stmt = ''.join(buf).strip()
            if stmt:
                stmts.append(stmt)
            buf = []
            continue

        buf.append(ch)

    tail = ''.join(buf).strip()
    if tail:
        stmts.append(tail)

    return stmts


def _safe_exec_idc(text):
    statements = _split_idc_statements(text)
    if not statements:
        return

    def _run():
        for stmt in statements:
            try:
                res = idc.eval_idc(stmt)
                try:
                    if hasattr(idc, "EVAL_FAILURE") and idc.EVAL_FAILURE(res):
                        _log("[remote_jump] IDC failure: %s -> %s\n" % (stmt, res))
                except Exception:
                    pass
            except Exception as e:
                _log("[remote_jump] IDC exception: %s -> %s\n" % (stmt, str(e)))

    try:
        flags = getattr(ida_kernwin, "MFF_WRITE", 0)
        ida_kernwin.execute_sync(_run, flags)
    except Exception as e:
        _log("[remote_jump] execute_sync(IDC) failed: %s\n" % str(e))


def _recv_exact(sock, count):
    data = b''
    while len(data) < count and not _stop_event.is_set():
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise ConnectionError("peer closed")
        data += chunk
    if _stop_event.is_set():
        raise ConnectionAbortedError("listener stopped")
    return data


def _handle_packet(sock):
    kind = _recv_exact(sock, 1)
    if kind == b'A':
        addr_size = _recv_exact(sock, 1)[0]
        if addr_size not in (4, 8):
            raise ValueError("unsupported addr_size=%d" % addr_size)
        addr_bytes = _recv_exact(sock, addr_size)
        addr = int.from_bytes(addr_bytes, byteorder='little', signed=False)
        _log("[remote_jump] got addr: 0x%0*X\n" % (addr_size * 2, addr))
        _safe_jumpto(addr)
        return

    if kind == b'I':
        length = struct.unpack('<I', _recv_exact(sock, 4))[0]
        payload = _recv_exact(sock, length) if length else b''
        text = payload.decode('utf-8', errors='replace')
        _log("[remote_jump] got idc buffer (%d bytes)\n" % length)
        _safe_exec_idc(text)
        return

    raise ValueError("unknown packet kind: %r" % kind)


def _listener_worker(host, port, reconnect_delay=2.0):
    global _stop_event
    _log("[remote_jump] listener thread starting, target %s:%d\n" % (host, port))

    while not _stop_event.is_set():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(5.0)
            s.connect((host, port))
            s.settimeout(None)
            _log("[remote_jump] connected to %s:%d\n" % (host, port))

            while not _stop_event.is_set():
                _handle_packet(s)

            try:
                s.close()
            except Exception:
                pass

        except Exception as e:
            try:
                s.close()
            except Exception:
                pass
            if not _stop_event.is_set():
                _log("[remote_jump] connection error: %s — reconnecting in %.1fs\n" % (str(e), reconnect_delay))
                t0 = time.time()
                while (time.time() - t0) < reconnect_delay and not _stop_event.is_set():
                    time.sleep(0.1)

    _log("[remote_jump] listener thread stopped\n")


def start_listener(host='127.0.0.1', port=27310):
    global _listener_thread, _stop_event
    if _listener_thread and _listener_thread.is_alive():
        _log("[remote_jump] already running\n")
        return

    _stop_event = threading.Event()
    _listener_thread = threading.Thread(target=_listener_worker, args=(host, port), daemon=True)
    _listener_thread.start()
    _log("[remote_jump] started (host=%s port=%d)\n" % (host, port))


def stop_listener():
    global _listener_thread, _stop_event
    if not _listener_thread:
        _log("[remote_jump] not running\n")
        return

    _stop_event.set()
    _listener_thread.join(timeout=2.0)

    if _listener_thread.is_alive():
        _log("[remote_jump] thread still alive (will stop when IDA exits)\n")
    else:
        _log("[remote_jump] stopped\n")

    _listener_thread = None
    _stop_event = None


if __name__ == "__main__":
    _log("[remote_jump] loaded.\n")
    start_listener(host='127.0.0.1', port=27310)
