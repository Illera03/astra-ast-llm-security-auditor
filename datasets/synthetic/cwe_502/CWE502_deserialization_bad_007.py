"""
CWE-502: Insecure Deserialization — Vulnerable
Pattern: dill.loads() on data received over a message queue.
Reference: NIST Juliet CWE-502, dill extends pickle and is equally unsafe.
"""

import dill
import redis


def worker_loop():
    r = redis.Redis(host="localhost", port=6379, db=0)
    while True:
        _, message = r.blpop("task_queue")
        task = dill.loads(message)
        result = task()
        r.rpush("result_queue", dill.dumps(result))


if __name__ == "__main__":
    worker_loop()
