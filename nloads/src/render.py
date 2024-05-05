import random
import jinja2

from utils import randstr


def gen_source_file(env: jinja2.Environment, template_name: str, **kwargs) -> str:
    tmpl = env.get_template(template_name)
    return tmpl.render(**kwargs)


def wrap_with_lib(
        env,
        wrapper_funcname: str,
        wrapped_func_prototype: str,
        wrapped_libname: str,
        wrapped_funcname: str,
) -> str:
    # parse prototype
    first_space_idx = wrapped_func_prototype.find(" ")
    first_paren_idx = wrapped_func_prototype.find("(")
    return_type = wrapped_func_prototype[: first_space_idx]
    func_proto_and_params = wrapped_func_prototype[first_paren_idx + 1:].strip(" )")
    proto_and_params = func_proto_and_params.split(",")

    func_proto = []
    func_params = []
    for pp in proto_and_params:
        pp = pp.strip(" ")
        last_space_idx = pp.rfind(" ")
        param_type = pp[:last_space_idx]
        param_name = pp[last_space_idx + 1:]

        func_proto.append(param_type)
        func_params.append(param_name)

    kwargs = {
        "return_type": return_type,
        "func_proto": ", ".join(func_proto),
        "func_params": ", ".join(func_params),
        "func_proto_and_params": func_proto_and_params,
        "ret_statement": "return " if return_type != "void" else "",
        "wrapper_funcname": wrapper_funcname,
        "wrapped_libname": wrapped_libname,
        "wrapped_funcname": wrapped_funcname,
    }
    wrapperlib_templates = ["wrapperlib0.c", "wrapperlib1.c", "wrapperlib2.c"]
    wrapperlib = random.choice(wrapperlib_templates)
    kwargs["good_filename"] = random.choice(["/etc/passwd", "/bin/sh", "/bin/cat"])
    kwargs["bad_filename"] = random.choice(["/etc", "/tmp", "/usr"]) + randstr(10)
    return gen_source_file(env, wrapperlib, **kwargs)
