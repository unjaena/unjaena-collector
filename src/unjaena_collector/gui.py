import os
import queue
import sys
import threading
import time
from typing import Any

try:
    import tkinter as tk
    from tkinter import messagebox, ttk
except ModuleNotFoundError:
    tk = None
    messagebox = None
    ttk = None

from .client import ServiceClient
from .runner import ProfileRunner

DEFAULT_SERVER_URL = os.environ.get("UNJAENA_SERVER_URL", "https://app.unjaena.com")


def _safe_text(value: Any, limit: int = 160) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ").strip()
    if len(text) > limit:
        return text[: limit - 3] + "..."
    return text


class CollectorApp:
    def __init__(self, root: Any):
        self.root = root
        self.root.title("Unjaena Collector")
        self.root.minsize(700, 520)
        self.events: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.worker: threading.Thread | None = None
        self.stop_event = threading.Event()
        self.show_token = tk.BooleanVar(value=False)
        self.server_var = tk.StringVar(value=DEFAULT_SERVER_URL)
        self.token_var = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="Ready")
        self.scanned_var = tk.StringVar(value="0")
        self.uploaded_var = tk.StringVar(value="0")
        self.skipped_var = tk.StringVar(value="0")
        self.failed_var = tk.StringVar(value="0")
        self._build()
        self.root.after(100, self._poll_events)

    def _build(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(4, weight=1)

        title = ttk.Label(self.root, text="Unjaena Collector", font=("Arial", 18, "bold"))
        title.grid(row=0, column=0, sticky="w", padx=18, pady=(16, 8))

        form = ttk.Frame(self.root)
        form.grid(row=1, column=0, sticky="ew", padx=18)
        form.columnconfigure(1, weight=1)

        ttk.Label(form, text="Server").grid(row=0, column=0, sticky="w", pady=6)
        self.server_entry = ttk.Entry(form, textvariable=self.server_var)
        self.server_entry.grid(row=0, column=1, sticky="ew", padx=(12, 0), pady=6)

        ttk.Label(form, text="Session token").grid(row=1, column=0, sticky="w", pady=6)
        token_frame = ttk.Frame(form)
        token_frame.grid(row=1, column=1, sticky="ew", padx=(12, 0), pady=6)
        token_frame.columnconfigure(0, weight=1)
        self.token_entry = ttk.Entry(token_frame, textvariable=self.token_var, show="*")
        self.token_entry.grid(row=0, column=0, sticky="ew")
        ttk.Checkbutton(token_frame, text="Show", variable=self.show_token, command=self._toggle_token).grid(row=0, column=1, padx=(10, 0))

        buttons = ttk.Frame(self.root)
        buttons.grid(row=2, column=0, sticky="ew", padx=18, pady=12)
        self.start_button = ttk.Button(buttons, text="Start collection", command=self._start)
        self.start_button.pack(side="left")
        self.stop_button = ttk.Button(buttons, text="Stop after current file", command=self._stop, state="disabled")
        self.stop_button.pack(side="left", padx=(10, 0))

        summary = ttk.Frame(self.root)
        summary.grid(row=3, column=0, sticky="ew", padx=18, pady=(0, 8))
        for idx, (label, var) in enumerate((
            ("Scanned", self.scanned_var),
            ("Uploaded", self.uploaded_var),
            ("Skipped", self.skipped_var),
            ("Failed", self.failed_var),
        )):
            box = ttk.Frame(summary, padding=(0, 6))
            box.grid(row=0, column=idx, sticky="ew", padx=(0 if idx == 0 else 10, 0))
            summary.columnconfigure(idx, weight=1)
            ttk.Label(box, text=label).pack(anchor="w")
            ttk.Label(box, textvariable=var, font=("Arial", 15, "bold")).pack(anchor="w")

        log_frame = ttk.Frame(self.root)
        log_frame.grid(row=4, column=0, sticky="nsew", padx=18, pady=(0, 12))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(1, weight=1)
        ttk.Label(log_frame, textvariable=self.status_var).grid(row=0, column=0, sticky="w", pady=(0, 6))
        self.progress = ttk.Progressbar(log_frame, mode="indeterminate")
        self.progress.grid(row=0, column=1, sticky="ew", padx=(12, 0), pady=(0, 6))
        self.log = tk.Text(log_frame, height=12, wrap="word", state="disabled")
        self.log.grid(row=1, column=0, columnspan=2, sticky="nsew")
        scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log.yview)
        scroll.grid(row=1, column=2, sticky="ns")
        self.log.configure(yscrollcommand=scroll.set)

    def _toggle_token(self) -> None:
        self.token_entry.configure(show="" if self.show_token.get() else "*")

    def _set_running(self, running: bool) -> None:
        state = "disabled" if running else "normal"
        self.start_button.configure(state=state)
        self.server_entry.configure(state=state)
        self.token_entry.configure(state=state)
        self.stop_button.configure(state="normal" if running else "disabled")
        if running:
            self.progress.start(12)
        else:
            self.progress.stop()

    def _log(self, message: str) -> None:
        now = time.strftime("%H:%M:%S")
        self.log.configure(state="normal")
        self.log.insert("end", f"[{now}] {message}\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _post(self, kind: str, payload: Any = None) -> None:
        self.events.put((kind, payload))

    def _start(self) -> None:
        server = self.server_var.get().strip().rstrip("/")
        token = self.token_var.get().strip()
        if not server:
            messagebox.showerror("Missing server", "Enter the service address.")
            return
        if not token:
            messagebox.showerror("Missing token", "Enter the session token.")
            return
        self.stop_event.clear()
        self._set_running(True)
        self.status_var.set("Connecting")
        self._log("Starting collection")
        self.worker = threading.Thread(target=self._run_worker, args=(server, token), daemon=True)
        self.worker.start()

    def _stop(self) -> None:
        self.stop_event.set()
        self.status_var.set("Stopping")
        self._log("Stop requested")

    def _run_worker(self, server: str, token: str) -> None:
        try:
            client = ServiceClient(server)
            self._post("status", "Authenticating")
            session = client.authenticate(token)
            self._post("status", "Loading collection profile")
            profile = client.get_profile(session)
            self._post("status", "Collecting")
            runner = ProfileRunner(client, session, profile, on_event=lambda e: self._post("runner", e), should_stop=self.stop_event.is_set)
            result = runner.run()
            self._post("done", result)
        except Exception as exc:
            self._post("error", _safe_text(exc))

    def _poll_events(self) -> None:
        while True:
            try:
                kind, payload = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == "status":
                self.status_var.set(_safe_text(payload, 80))
                self._log(_safe_text(payload))
            elif kind == "runner":
                self._handle_runner_event(dict(payload or {}))
            elif kind == "done":
                self._handle_done(dict(payload or {}))
            elif kind == "error":
                self.status_var.set("Failed")
                self._log(f"Error: {_safe_text(payload)}")
                self._set_running(False)
                messagebox.showerror("Collection failed", _safe_text(payload, 240))
        self.root.after(100, self._poll_events)

    def _handle_runner_event(self, event: dict[str, Any]) -> None:
        name = _safe_text(event.get("name"), 80)
        kind = event.get("event")
        for key, var in (("scanned", self.scanned_var), ("uploaded", self.uploaded_var), ("skipped", self.skipped_var), ("failed", self.failed_var)):
            if key in event:
                var.set(str(event[key]))
        if kind == "started":
            self._log("Collection profile accepted")
        elif kind == "target_started":
            self.status_var.set("Scanning")
        elif kind == "file_scanned":
            self.status_var.set("Scanning files")
        elif kind == "hashing":
            self.status_var.set(f"Hashing {name}")
        elif kind == "protecting":
            self.status_var.set(f"Preparing {name}")
        elif kind == "uploading":
            self.status_var.set(f"Uploading {name}")
        elif kind == "file_uploaded":
            self._log(f"Uploaded {name}")
        elif kind == "file_skipped":
            self._log(f"Skipped {name}")
        elif kind == "file_failed":
            self._log(f"Failed {name}: {_safe_text(event.get('error'), 120)}")
        elif kind == "stopped":
            self._log("Collection stopped")
        elif kind == "finished":
            self._log("Collection finished")

    def _handle_done(self, result: dict[str, Any]) -> None:
        self.scanned_var.set(str(result.get("scanned", 0)))
        self.uploaded_var.set(str(result.get("uploaded", 0)))
        self.skipped_var.set(str(result.get("skipped", 0)))
        self.failed_var.set(str(result.get("failed", 0)))
        self.status_var.set("Completed" if int(result.get("failed", 0) or 0) == 0 else "Completed with errors")
        self._set_running(False)
        self._log("Done")


def main() -> int:
    if tk is None:
        print("Graphical desktop support is not available in this Python runtime.", file=sys.stderr)
        return 1
    root = tk.Tk()
    CollectorApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
