from contextlib import contextmanager
from time import perf_counter


def create_timings():
    return {}


@contextmanager
def measure_stage(timings, stage_name):
    started_at = perf_counter()

    try:
        yield
    finally:
        timings[stage_name] = round(perf_counter() - started_at, 3)
