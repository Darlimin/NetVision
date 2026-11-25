import os
import sys
import threading
import time


class DuplicateExecutionDetector:
    """
    Отслеживает функции, которые срабатывают в одно и то же миллисекундное окно
    (например, при клике в UI), обращаясь к одним и тем же внутренним операциям.
    Потокобезопасен для использования с WorkerRegistry.
    """

    def __init__(self, project_root, time_window_ms=40):
        self.project_root = os.path.abspath(project_root)
        self.window = time_window_ms / 1000.0
        self.recent_calls = []
        self.local = threading.local()  # Изолированный стек вызовов для каждого потока
        self.reported_pairs = set()
        self._lock = threading.Lock()

    def _get_stack(self):
        if not hasattr(self.local, "stack"):
            self.local.stack = []
        return self.local.stack

    def profiler(self, frame, event, arg):
        stack = self._get_stack()
        if event == "call":
            filename = os.path.abspath(frame.f_code.co_filename)
            if (
                filename.startswith(self.project_root)
                and ".venv" not in filename
                and "venv" not in filename
            ):
                func_name = frame.f_code.co_name
                if not func_name.startswith("<"):
                    rel_file = os.path.relpath(filename, self.project_root)
                    ident = f"{rel_file}:{func_name}:{frame.f_code.co_firstlineno}"
                    stack.append({"id": ident, "time": time.perf_counter(), "subcalls": set()})
            else:
                if stack:
                    stack[-1]["subcalls"].add(frame.f_code.co_name)

        elif event == "return" and stack:
            filename = os.path.abspath(frame.f_code.co_filename)
            if (
                filename.startswith(self.project_root)
                and ".venv" not in filename
                and "venv" not in filename
            ):
                func_name = frame.f_code.co_name
                if not func_name.startswith("<") and stack:
                    finished = stack.pop()
                    if len(finished["subcalls"]) >= 2:
                        with self._lock:
                            self._check_collision(finished)

    def _check_collision(self, current):
        now = current["time"]
        self.recent_calls = [c for c in self.recent_calls if now - c["time"] <= self.window]

        for past in self.recent_calls:
            if past["id"] != current["id"]:
                shared_work = past["subcalls"] & current["subcalls"]
                union_work = past["subcalls"] | current["subcalls"]
                if len(shared_work) >= 3 and (len(shared_work) / len(union_work)) >= 0.6:
                    pair = tuple(sorted([past["id"], current["id"]]))
                    if pair not in self.reported_pairs:
                        self.reported_pairs.add(pair)
                        print(
                            f"\n[RUNTIME SHADOW ALERT] Две разные функции выполнили одинаковую работу за <{self.window * 1000:.0f}мс!"
                        )
                        print(f"  1) {pair[0]}")
                        print(f"  2) {pair[1]}")
                        print(f"  Общие внутренние операции: {shared_work}")

        self.recent_calls.append(current)

    def start(self):
        sys.setprofile(self.profiler)
        threading.setprofile(self.profiler)

    def stop(self):
        sys.setprofile(None)
        threading.setprofile(None)
