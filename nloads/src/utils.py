import string
import random


def randstr(n: int) -> str:
    charset = string.ascii_letters
    return "".join(random.choice(charset) for _ in range(n))
