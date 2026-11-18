import os
import sys


def main() -> int:
    # 1. Включаем Runtime-детектор двойных вызовов только по флагу --audit
    detector = None
    if "--audit" in sys.argv:
        from netvision.debug_profiler import DuplicateExecutionDetector

        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        detector = DuplicateExecutionDetector(project_root=project_root)
        detector.start()
        print("[AUDIT MODE] Отслеживание дублирующихся вызовов активно...")

    from netvision.app import main as app_main

    try:
        return int(app_main() or 0)
    finally:
        if detector:
            detector.stop()


if __name__ == "__main__":
    raise SystemExit(main())
