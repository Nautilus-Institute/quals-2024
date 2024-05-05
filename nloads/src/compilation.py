from typing import Optional
import tempfile
import os
import subprocess
import shutil

from render import gen_source_file


def compile_c_plain(
        arch: str,
        source: str,
        dst_path: str,
        passphrase: Optional[bytes],
        mp_lock,
        static=False,
        debug=False) -> None:
    """
    Zero protection whatsoever
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        src_path = os.path.join(tmpdir, "src.c")
        tmp_dst_path = os.path.join(tmpdir, "dst")
        tmp_dst_obj_path = os.path.join(tmpdir, "dst.o")
        tmp_dst_asm_path = os.path.join(tmpdir, "dst.s")
        with open(src_path, "w") as f:
            f.write(source)

        if arch == "x86_64":
            gpp = "gcc"
            strip = "strip"
        else:
            raise NotImplementedError(f"Unknown arch {arch}")

        src = [src_path]
        if static:
            static_ = ["-static"]
        else:
            static_ = []
        if debug:
            subprocess.check_call(
                [gpp, "-g"]
                + static_
                + src
                + [
                    "-DUSE_LIBS",
                    "-S",
                    "-masm=intel",
                    "-fcf-protection=none",
                    "-fno-stack-protector",
                    "-Wno-format-security",
                    "-o",
                    tmp_dst_asm_path,
                    "-Wno-unused-result",
                ],
                stdin=subprocess.DEVNULL,
                shell=False,
            )
        else:
            subprocess.check_call(
                [gpp, "-O2"]
                + static_
                + src
                + [
                    "-DUSE_LIBS",
                    "-S",
                    "-masm=intel",
                    "-fcf-protection=none",
                    "-fno-stack-protector",
                    "-Wno-format-security",
                    "-o",
                    tmp_dst_asm_path,
                    "-Wno-unused-result",
                ],
                stdin=subprocess.DEVNULL,
                shell=False,
            )

        subprocess.check_call(
            [gpp, tmp_dst_asm_path] + ["-c", "-o", tmp_dst_obj_path], stdin=subprocess.DEVNULL, shell=False
        )
        subprocess.check_call(
            [gpp, tmp_dst_obj_path] + ["-o", tmp_dst_path, "-ldl"], stdin=subprocess.DEVNULL, shell=False
        )
        if not debug:
            subprocess.check_call([strip, "--strip-all", tmp_dst_path], stdin=subprocess.DEVNULL, shell=False)

        # ensure the output directory exists
        base_dir = os.path.dirname(dst_path)
        try:
            os.mkdir(base_dir)
        except FileExistsError:
            pass

        shutil.move(tmp_dst_path, dst_path)


def compile_lib_plain(
        arch: str,
        source: str,
        dst_path: str,
        passphrase: Optional[bytes],
        mp_lock,
        static=False,
        debug=False,
) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        src_path = os.path.join(tmpdir, "src.c")
        tmp_dst_path = os.path.join(tmpdir, "dst")
        tmp_dst_obj_path = os.path.join(tmpdir, "dst.o")
        tmp_dst_asm_path = os.path.join(tmpdir, "dst.s")
        with open(src_path, "w") as f:
            f.write(source)

        if arch == "x86_64":
            gpp = "gcc"
            strip = "strip"
        else:
            raise NotImplementedError(f"Unknown arch {arch}")

        src = [src_path]
        if static:
            static_ = ["-static"]
        else:
            static_ = []
        if debug:
            subprocess.check_call(
                [gpp, "-g"]
                + static_
                + src
                + [
                    "-DUSE_LIBS",
                    "-S",
                    "-masm=intel",
                    "-fcf-protection=none",
                    "-fno-stack-protector",
                    "-Wno-format-security",
                    "-o",
                    tmp_dst_asm_path,
                    "-Wno-unused-result",
                    "-fPIC",
                ],
                stdin=subprocess.DEVNULL,
                shell=False,
            )
        else:
            subprocess.check_call(
                [gpp, "-O2"]
                + static_
                + src
                + [
                    "-DUSE_LIBS",
                    "-S",
                    "-masm=intel",
                    "-fcf-protection=none",
                    "-fno-stack-protector",
                    "-Wno-format-security",
                    "-o",
                    tmp_dst_asm_path,
                    "-Wno-unused-result",
                    "-fPIC",
                ],
                stdin=subprocess.DEVNULL,
                shell=False,
            )

        subprocess.check_call(
            [gpp, tmp_dst_asm_path] + ["-c", "-o", tmp_dst_obj_path], stdin=subprocess.DEVNULL, shell=False
        )
        subprocess.check_call(
            [gpp, tmp_dst_obj_path] + ["-o", tmp_dst_path, "-ldl", "-shared"], stdin=subprocess.DEVNULL, shell=False
        )
        if not debug:
            subprocess.check_call([strip, "--strip-all", tmp_dst_path], stdin=subprocess.DEVNULL, shell=False)

        # ensure the output directory exists
        base_dir = os.path.dirname(dst_path)
        try:
            os.mkdir(base_dir)
        except FileExistsError:
            pass

        shutil.move(tmp_dst_path, dst_path)
