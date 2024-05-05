from typing import List
import os
import struct
import subprocess
import base64
import re
import sys
import random
import multiprocessing
from concurrent.futures import ProcessPoolExecutor

from rich.progress import (
    Progress,
    BarColumn,
    TextColumn,
    TaskProgressColumn,
    TimeRemainingColumn,
    TimeElapsedColumn,
    MofNCompleteColumn,
)


DEBUG = False
BASEDIR = os.path.dirname(os.path.abspath(__file__))


def chop_data(data: bytes) -> List[int]:
    lst = []
    for i in range(0, len(data), 8):
        chunk = data[i : i + 8]
        if len(chunk) < 8:
            chunk = chunk + b"\x00" * (8 - len(chunk))
        lst.append(struct.unpack("<Q", chunk)[0])
    return lst


def verify_binaries(
    all_workers: int,
    n: int,
    task_id,
    chopped_ints: List[int],
    output_dir: str,
    progress,
):
    successes, failures = 0, []
    for idx, int_ in enumerate(chopped_ints):
        if idx % all_workers == n:
            binary_path = f"{output_dir}/{idx}/beatme"
            binary_path = os.path.join(BASEDIR, binary_path)
            cmd = [binary_path]

            chopped_bytes = int_.to_bytes(8, "little")
            all_input = chopped_bytes

            proc = subprocess.Popen(
                cmd,
                cwd=os.path.dirname(binary_path),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, stderr = proc.communicate(all_input)
            stdout = stdout.decode("utf-8")

            if ":)" in stdout and ":(" not in stdout:
                successes += 1
            elif ":(" in stdout and ":)" not in stdout:
                status = (
                    f"Failure with binary {binary_path}. Intended input: {base64.b64encode(all_input).decode('utf-8')}"
                )
                failures.append((binary_path, status))
            else:
                status = f"Failure with binary {binary_path} - unexpected output. Intended input: {base64.b64encode(all_input).decode('utf-8')}"
                failures.append((binary_path, status))

            # try a bunch of bad input
            for i in range(10):
                new_chopped_bytes = (
                    int_ ^ (1 << random.randint(0, 63))
                    if random.randint(0, 1) == 0
                    else int_ | (1 << random.randint(0, 63))
                ).to_bytes(8, "little")

                all_input = new_chopped_bytes
                proc = subprocess.Popen(
                    cmd,
                    cwd=os.path.dirname(binary_path),
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                stdout, stderr = proc.communicate(all_input)
                stdout = stdout.decode("utf-8")

                if new_chopped_bytes == chopped_bytes:
                    if ":)" in stdout and ":(" not in stdout:
                        pass
                    else:
                        status = f"Subtest: Failure with binary {binary_path}. Intended input: {base64.b64encode(all_input).decode('utf-8')}"
                        failures.append((binary_path, status))
                else:
                    if ":)" in stdout and ":(" not in stdout:
                        status = f"Subtest: Failure with binary {binary_path}. Intended *failing* input: {base64.b64encode(all_input).decode('utf-8')}. Original input: {base64.b64encode(chopped_bytes).decode('utf-8')}"
                        failures.append((binary_path, status))
                    else:
                        pass

        progress[task_id] = {
            "progress": idx + 1,
            "total": len(chopped_ints),
            "successes": successes,
            "failures": failures,
        }


def main():
    img_path = "flag.jpg"
    output_dir = "output"

    with open(img_path, "rb") as f:
        data = f.read()

    chopped_ints = chop_data(data)

    progress = Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        expand=True,
    )
    nworkers = 1 if len(sys.argv) == 1 else int(sys.argv[1])

    successes, failures = 0, []
    with progress:
        futures = []  # keep track of the jobs
        processed_failures = set()
        with multiprocessing.Manager() as manager:
            # this is the key - we share some state between our
            # main process and our worker functions
            _progress = manager.dict()
            overall_progress_task = progress.add_task("[green]All jobs progress:")

            with ProcessPoolExecutor(max_workers=nworkers) as executor:
                for n in range(0, nworkers):  # iterate over the jobs we need to run
                    # set visible false so we don't have a lot of bars all at once:
                    task_id = progress.add_task(f"task {n}", visible=False)
                    futures.append(
                        executor.submit(
                            verify_binaries,
                            nworkers,
                            n,
                            task_id,
                            chopped_ints,
                            output_dir,
                            _progress,
                        )
                    )

                # monitor the progress:
                while (n_finished := sum([future.done() for future in futures])) < len(futures):
                    progress.update(overall_progress_task, completed=n_finished, total=len(futures))
                    for task_id, update_data in _progress.items():
                        latest = update_data["progress"]
                        total = update_data["total"]
                        if update_data["failures"]:
                            for item in update_data["failures"]:
                                if item not in processed_failures:
                                    processed_failures.add(item)
                                    progress.console.print(item)
                        # update the progress bar for this task:
                        progress.update(
                            task_id,
                            completed=latest,
                            total=total,
                            visible=latest < total,
                        )

                # raise any errors:
                for future in futures:
                    future.result()
                for update_data in _progress.values():
                    successes += update_data["successes"]
                    failures += update_data["failures"]

    print(f"Successes: {successes}, failures: {len(failures)}")
    if failures:
        for f in failures:
            print(f"{f[0]}: {f[1]}")


if __name__ == "__main__":
    main()
