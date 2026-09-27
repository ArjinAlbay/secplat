from __future__ import annotations

import os
import signal
import subprocess
import threading
from collections.abc import Callable, Sequence

from secplat.domain.scanning.ports import RunOutcome, ToolRunner


class SubprocessToolRunner(ToolRunner):
    def __init__(self, max_stderr_bytes: int = 4096) -> None:
        self._max_stderr = max_stderr_bytes

    def run(
        self, argv: Sequence[str], timeout_s: int, on_line: Callable[[str], None]
    ) -> RunOutcome:
        timed_out = threading.Event()
        proc = subprocess.Popen(
            list(argv),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        stderr_buf = bytearray()

        def _drain_stderr() -> None:
            if proc.stderr is None:
                return
            while True:
                chunk = proc.stderr.read(4096)
                if not chunk:
                    break
                stderr_buf.extend(chunk)
                excess = len(stderr_buf) - self._max_stderr
                if excess > 0:
                    del stderr_buf[:excess]

        stderr_thread = threading.Thread(target=_drain_stderr, daemon=True)
        stderr_thread.start()

        def _kill_on_timeout() -> None:
            timed_out.set()
            self._kill_group(proc, signal.SIGKILL)

        timeout_timer = threading.Timer(timeout_s, _kill_on_timeout)
        timeout_timer.start()
        try:
            if proc.stdout is not None:
                for raw_line in proc.stdout:
                    line = raw_line.decode("utf-8", errors="replace").strip()
                    if line:
                        on_line(line)
            proc.wait()
        finally:
            timeout_timer.cancel()
            if proc.poll() is None:
                self._kill_group(proc, signal.SIGTERM)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._kill_group(proc, signal.SIGKILL)
                    proc.wait()
            stderr_thread.join(timeout=5)
        tail = bytes(stderr_buf[-self._max_stderr :]).decode("utf-8", errors="replace")
        return RunOutcome(
            returncode=proc.returncode or 0,
            stderr_tail=tail,
            timed_out=timed_out.is_set(),
        )

    @staticmethod
    def _kill_group(proc: subprocess.Popen[bytes], sig: signal.Signals) -> None:
        try:
            os.killpg(os.getpgid(proc.pid), sig)
        except (ProcessLookupError, PermissionError):
            proc.send_signal(sig)
