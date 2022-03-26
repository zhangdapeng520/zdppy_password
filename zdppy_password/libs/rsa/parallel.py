import multiprocessing as mp
from multiprocessing.connection import Connection
from . import prime, randnum


def _find_prime(nbits: int, pipe: Connection) -> None:
    while True:
        integer = randnum.read_random_odd_int(nbits)

        # Test for primeness
        if prime.is_prime(integer):
            pipe.send(integer)
            return


def getprime(nbits: int, poolsize: int) -> int:
    """Returns a prime number that can be stored in 'nbits' bits.

    Works in multiple threads at the same time.

    >>> p = getprime(128, 3)
    >>> rsa.prime.is_prime(p-1)
    False
    >>> rsa.prime.is_prime(p)
    True
    >>> rsa.prime.is_prime(p+1)
    False

    >>> from rsa import common
    >>> common.bit_size(p) == 128
    True

    """

    (pipe_recv, pipe_send) = mp.Pipe(duplex=False)

    # Create processes
    try:
        procs = [mp.Process(target=_find_prime, args=(nbits, pipe_send)) for _ in range(poolsize)]
        # Start processes
        for p in procs:
            p.start()

        result = pipe_recv.recv()
    finally:
        pipe_recv.close()
        pipe_send.close()

    # Terminate processes
    for p in procs:
        p.terminate()

    return result


__all__ = ["getprime"]

if __name__ == "__main__":
    print("Running doctests 1000x or until failure")
    import doctest

    for count in range(100):
        (failures, tests) = doctest.testmod()
        if failures:
            break

        if count % 10 == 0 and count:
            print("%i times" % count)

    print("Doctests done")
