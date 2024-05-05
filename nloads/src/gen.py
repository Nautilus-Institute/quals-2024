from typing import List, Callable, Dict
import sys
import random
import struct
import os
import shutil
import multiprocessing
from concurrent.futures import ProcessPoolExecutor

import jinja2
from rich.progress import (
    Progress,
    BarColumn,
    TextColumn,
    TaskProgressColumn,
    TimeRemainingColumn,
    TimeElapsedColumn,
    MofNCompleteColumn,
)

from compilation import compile_c_plain, compile_lib_plain
from render import gen_source_file, wrap_with_lib
from utils import randstr


DEBUG = False
STATIC = False


# tmpl_0: tea
from ctypes import c_uint32


def tea_encrypt(v, k):
    y = c_uint32(v[0])
    z = c_uint32(v[1])
    sum = c_uint32(0)
    delta = 0x9e3779b9
    n = 32
    w = [0, 0]

    while n > 0:
        sum.value += delta
        y.value += (z.value << 4) + k[0] ^ z.value + sum.value ^ (z.value >> 5) + k[1]
        z.value += (y.value << 4) + k[2] ^ y.value + sum.value ^ (y.value >> 5) + k[3]
        n -= 1

    w[0] = y.value
    w[1] = z.value
    return w


def t0_args(plain: int):
    # random key
    key_lo = random.randint(0, 0xFFFF_FFFF_FFFF_FFFF)
    key0 = key_lo & 0xFFFF_FFFF
    key1 = (key_lo >> 32) & 0xFFFF_FFFF
    key_hi = random.randint(0, 0xFFFF_FFFF_FFFF_FFFF)
    key2 = key_hi & 0xFFFF_FFFF
    key3 = (key_hi >> 32) & 0xFFFF_FFFF

    # randomize macros
    macros_n = {}
    for i in range(18):
        macros_n[f"add_n{i}"] = random.randint(1, 6)
        macros_n[f"xor_n{i}"] = random.randint(1, 2)

    # random numbers
    rand_numbers = {}
    for i in range(1, 7):
        rand_numbers[f"add{i}_rand"] = random.randint(0, 0x7fff_ffff)
        rand_numbers[f"sub{i}_rand"] = random.randint(0, 0x7fff_ffff)
        rand_numbers[f"xor{i}_rand"] = random.randint(0, 0x7fff_ffff)

    # library name and func names
    libs = {}
    for i in range(1, 7):
        libs[f"add{i}_libname"] = f"./{randstr(16)}.so"
        libs[f"add{i}_libfuncname"] = f"{randstr(16)}"
        libs[f"sub{i}_libname"] = f"./{randstr(16)}.so"
        libs[f"sub{i}_libfuncname"] = f"{randstr(16)}"
    for i in range(1, 3):
        libs[f"xor{i}_libname"] = f"./{randstr(16)}.so"
        libs[f"xor{i}_libfuncname"] = f"{randstr(16)}"
    for i in range(1, 5):
        libs[f"rand{i}_libname"] = f"./{randstr(16)}.so"
        libs[f"rand{i}_libfuncname"] = f"{randstr(16)}"

    # random numbers for key permutation
    for i in range(1, 5):
        rand_numbers[f"rand{i}_key"] = random.randint(0, 0x7fff_ffff)
        rand_numbers[f"rand{i}"] = random.randint(0, 0x7fff_ffff)

    k0 = key0 ^ rand_numbers["rand1_key"] ^ rand_numbers["rand1"]
    k1 = key1 ^ ((rand_numbers["rand2_key"] + rand_numbers["rand2"]) & 0xffff_ffff)
    k2 = ((key2 + rand_numbers["rand3_key"]) & 0xffff_ffff) ^ rand_numbers["rand3"]
    k3 = ((key3 - rand_numbers["rand4_key"]) & 0xffff_ffff) ^ rand_numbers["rand4"]
    repeat = random.randint(1, 32)
    c = [plain & 0xffff_ffff, plain >> 32]
    for i in range(repeat):
        c = tea_encrypt(c, [k0, k1, k2, k3])

    return {
        "c": ((c[1] << 32) & 0xffff_ffff_0000_0000) | c[0],
        "k0": key0,
        "k1": key1,
        "k2": key2,
        "k3": key3,
        "repeat": repeat,
    } | macros_n | rand_numbers | libs


# tmpl_1: bit shuffling

def t1_args(plain: int):
    def t1_transform(n: int) -> int:
        mapping: Dict[int, int] = {
            0: 5,
            1: 6,
            2: 7,
            3: 4,
            4: 0,
            5: 1,
            6: 3,
            7: 2,
        }
        stream = bin(n)[2:].rjust(8, "0")[::-1]
        new_stream = [None] * 8
        for i in range(8):
            new_stream[mapping[i]] = stream[i]
        new_stream = new_stream[::-1]
        # stream = stream[::-1]
        return int("".join(new_stream), 2)

    plain_lo = plain & 0xFFFF_FFFF
    plain_hi = (plain >> 32) & 0xFFFF_FFFF
    p0, p1, p2, p3 = plain_lo & 0xFF, (plain_lo >> 8) & 0xFF, (plain_lo >> 16) & 0xFF, (plain_lo >> 24) & 0xFF
    p4, p5, p6, p7 = plain_hi & 0xFF, (plain_hi >> 8) & 0xFF, (plain_hi >> 16) & 0xFF, (plain_hi >> 24) & 0xFF
    k0 = t1_transform(p0)
    k1 = t1_transform(p1)
    k2 = t1_transform(p2)
    k3 = t1_transform(p3)
    k4 = t1_transform(p4)
    k5 = t1_transform(p5)
    k6 = t1_transform(p6)
    k7 = t1_transform(p7)

    # library name and func names
    libs = {}
    for i in range(1, 4):
        libs[f"transform{i}_libname"] = f"./{randstr(16)}.so"
        libs[f"transform{i}_libfuncname"] = f"{randstr(16)}"

    return {
        "k0": k0,
        "k1": k1,
        "k2": k2,
        "k3": k3,
        "k4": k4,
        "k5": k5,
        "k6": k6,
        "k7": k7,
        "sigsegv_handler": 1 if random.randint(1, 128) == 1 else 0,
    } | libs


# tmpl_2: ROT-N

def t2_args(plain: int):
    plain_lo = plain & 0xFFFF_FFFF
    plain_hi = (plain >> 32) & 0xFFFF_FFFF
    p0, p1, p2, p3 = plain_lo & 0xFF, (plain_lo >> 8) & 0xFF, (plain_lo >> 16) & 0xFF, (plain_lo >> 24) & 0xFF
    p4, p5, p6, p7 = plain_hi & 0xFF, (plain_hi >> 8) & 0xFF, (plain_hi >> 16) & 0xFF, (plain_hi >> 24) & 0xFF

    rotations = {}
    for i in range(1, 4):
        rotations[f"rotation{i}"] = random.randint(1, 0xc0)

    # determine which table_lookup function to call
    sequences = []
    for i in range(8):
        sequences.append(random.randint(1, 3))
    seqs = dict((f"seq{i}", str(seq)) for i, seq in enumerate(sequences))

    k0 = (p0 + rotations[f"rotation{sequences[0]}"]) & 0xFF
    k1 = (p1 + rotations[f"rotation{sequences[1]}"]) & 0xFF
    k2 = (p2 + rotations[f"rotation{sequences[2]}"]) & 0xFF
    k3 = (p3 + rotations[f"rotation{sequences[3]}"]) & 0xFF
    k4 = (p4 + rotations[f"rotation{sequences[4]}"]) & 0xFF
    k5 = (p5 + rotations[f"rotation{sequences[5]}"]) & 0xFF
    k6 = (p6 + rotations[f"rotation{sequences[6]}"]) & 0xFF
    k7 = (p7 + rotations[f"rotation{sequences[7]}"]) & 0xFF

    # library name and func names
    libs = {}
    for i in range(1, 4):
        libs[f"tablelookup{i}_libname"] = f"./{randstr(16)}.so"
        libs[f"tablelookup{i}_libfuncname"] = f"{randstr(16)}"
    # random numbers
    random_numbers = {}
    for i in range(0, 8):
        random_numbers[f"rnd{i}"] = random.randint(0, 0x7ff_ffff)


    return {
        "k0": k0,
        "k1": k1,
        "k2": k2,
        "k3": k3,
        "k4": k4,
        "k5": k5,
        "k6": k6,
        "k7": k7,
    } | libs | random_numbers | rotations | seqs


class Template:
    def __init__(
        self,
        template_name: str,
        lib_templates: Dict[str, List[str]],
        arches: List[str],
        arg_func: Callable,
        compile_funcs: List[Callable],
        lib_compile_funcs: List[Callable],
    ):
        self.template_name = template_name
        self.lib_templates = lib_templates
        self.arches = arches
        self.arg_func = arg_func
        self.compile_funcs = compile_funcs
        self.lib_compile_funcs = lib_compile_funcs


# Template 0
TMPL0 = Template(
    "tmpl0.c",
    {
        "add": ["tmpl0_add1.c", "tmpl0_add2.c", "tmpl0_add3.c", "tmpl0_add4.c", "tmpl0_add5.c", "tmpl0_add6.c"],
        "sub": ["tmpl0_sub1.c", "tmpl0_sub2.c", "tmpl0_sub3.c", "tmpl0_sub4.c", "tmpl0_sub5.c", "tmpl0_sub6.c"],
        "xor": ["tmpl0_xor1.c", "tmpl0_xor2.c"],
        "rand": ["tmpl0_rand1.c", "tmpl0_rand2.c", "tmpl0_rand3.c", "tmpl0_rand4.c"],
    },
    [
        "x86_64",
    ],
    t0_args,
    [
        compile_c_plain,
    ],
    [
        compile_lib_plain,
    ],
)
# Template 1
TMPL1 = Template(
    "tmpl1.c",
    {
        "transform": ["tmpl1_transform1.c", "tmpl1_transform2.c", "tmpl1_transform3.c"],
    },
    [
        "x86_64",
    ],
    t1_args,
    [
        compile_c_plain,
    ],
    [
        compile_lib_plain,
    ],
)
# Template 2
TMPL2 = Template(
    "tmpl2.c",
    {
        "tablelookup": ["tmpl2_tablelookup1.c", "tmpl2_tablelookup2.c", "tmpl2_tablelookup3.c"],
    },
    [
        "x86_64",
    ],
    t2_args,
    [
        compile_c_plain,
    ],
    [
        compile_lib_plain,
    ],
)


TEMPLATES: List[Template] = [
    TMPL0,
    # TMPL1,
    # TMPL2,
]


def chop_data(data: bytes) -> List[int]:
    lst = []
    for i in range(0, len(data), 8):
        chunk = data[i : i + 8]
        if len(chunk) < 8:
            chunk = chunk + b"\x00" * (8 - len(chunk))
        lst.append(struct.unpack("<Q", chunk)[0])
    return lst


def build_binaries(
    all_workers: int,
    n: int,
    task_id,
    chopped_ints: List[int],
    templates_expanded: List,
    output_dir_base: str,
    mp_lock,
    progress,
):
    env = jinja2.Environment(loader=jinja2.FileSystemLoader("templates/"))
    random.seed(0x1337 + n)  # seed the process
    for idx, int_ in enumerate(chopped_ints):
        if idx % all_workers == n:
            tmpl, lib_tmpls, arches, get_args, compile_, lib_compile_ = random.choice(templates_expanded)

            arch = random.choice(arches)
            kwargs = get_args(int_)
            output_dir = os.path.join(output_dir_base, str(idx))

            # main source
            src = gen_source_file(env, tmpl, **kwargs)
            try:
                shutil.rmtree(output_dir)
            except FileNotFoundError:
                pass

            dst = os.path.join(output_dir, "beatme")
            compile_(arch, src, dst, 0, mp_lock, static=STATIC, debug=DEBUG)

            # libraries
            for libname, lib_tmpl_candidates in lib_tmpls.items():
                for lib_idx, lib_tmpl in enumerate(lib_tmpl_candidates):
                    lib_kwargs = dict(kwargs)
                    lib_kwargs["libname"] = kwargs[f"{libname}{lib_idx + 1}_libname"]
                    lib_kwargs["funcname"] = kwargs[f"{libname}{lib_idx + 1}_libfuncname"]

                    # wrap it!
                    wrap_count = random.randint(0, 4)
                    for i in range(wrap_count):
                        wrapper_libname = lib_kwargs["libname"]
                        wrapper_funcname = lib_kwargs["funcname"]
                        new_libname = f"./{randstr(16)}.so"
                        new_funcname = f"{randstr(16)}"
                        wrapper_src = wrap_with_lib(env, wrapper_funcname, "uint32_t foo(uint32_t a, uint32_t b, uint32_t c)", new_libname, new_funcname)
                        dst = os.path.join(output_dir, wrapper_libname)
                        lib_compile_(arch, wrapper_src, dst, 0, mp_lock, static=STATIC, debug=DEBUG)
                        lib_kwargs["libname"] = new_libname
                        lib_kwargs["funcname"] = new_funcname

                    src = gen_source_file(env, lib_tmpl, **lib_kwargs)
                    dst = os.path.join(output_dir, lib_kwargs["libname"])
                    lib_compile_(arch, src, dst, 0, mp_lock, static=STATIC, debug=DEBUG)

        progress[task_id] = {"progress": idx + 1, "total": len(chopped_ints)}


def main():
    img_path = "flag.jpg"
    output_dir = "output"

    with open(img_path, "rb") as f:
        data = f.read()

    chopped_ints = chop_data(data)

    # expand TEMPLATES
    templates_expanded = []
    for template in TEMPLATES:
        for compile_choice in template.compile_funcs:
            for libcompile_choice in template.lib_compile_funcs:
                templates_expanded.append(
                    (template.template_name,
                     template.lib_templates,
                     template.arches,
                     template.arg_func,
                     compile_choice,
                     libcompile_choice,
                     )
                )

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
    with progress:
        futures = []  # keep track of the jobs
        with multiprocessing.Manager() as manager:
            # this is the key - we share some state between our
            # main process and our worker functions
            _progress = manager.dict()
            overall_progress_task = progress.add_task("[green]All jobs progress:")
            mp_lock = manager.Lock()

            with ProcessPoolExecutor(max_workers=nworkers) as executor:
                for n in range(0, nworkers):  # iterate over the jobs we need to run
                    # set visible false so we don't have a lot of bars all at once:
                    task_id = progress.add_task(f"task {n}", visible=False)
                    futures.append(
                        executor.submit(
                            build_binaries,
                            nworkers,
                            n,
                            task_id,
                            chopped_ints,
                            templates_expanded,
                            output_dir,
                            mp_lock,
                            _progress,
                        )
                    )

                # monitor the progress:
                while (n_finished := sum([future.done() for future in futures])) < len(futures):
                    progress.update(overall_progress_task, completed=n_finished, total=len(futures))
                    for task_id, update_data in _progress.items():
                        latest = update_data["progress"]
                        total = update_data["total"]
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


if __name__ == "__main__":
    main()
