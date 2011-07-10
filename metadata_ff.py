#!/usr/bin/env python3

import errno
import logging

def res_data(path):
    from logging import getLogger
    logger = getLogger()
    from subprocess import Popen, PIPE, CalledProcessError, list2cmdline
    def preexec_fn():
        from resource import setrlimit, RLIMIT_CPU
        # give the process 1 second, 2 if it treats SIGXCPU
        setrlimit(RLIMIT_CPU, (1, 2))
    args = ['ffprobe', '-show_format', path]
    try:
        p = Popen(
            args,
            stdout=PIPE,
            stderr=PIPE,
            preexec_fn=preexec_fn,
            close_fds=True
        )
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            logging.error('Failed to open %r: %s', list2cmdline(args), exc)
            return {}
        else:
            raise
    stdout, stderr = p.communicate()
    if p.wait() != 0:
        logger.warning('{!r} failed with exit code {:d}'.format(
            list2cmdline(args),
            p.returncode))
        return {}
    # TODO an alternative here could be to try several encodings in succession:
    # utf-8, cp1252, and the western european one whatever it is
    pusher = (l.rstrip() for l in stdout.decode('cp1252', errors='ignore').splitlines())
    data = {}
    def format():
        for line in pusher:
            if line == '[/FORMAT]':
                return
            try:
                tag, value = map(str.strip, line.split('=', 1))
            except ValueError as exc:
                logging.error('Error parsing ffprobe format output line %r for file %r', line, path)
                continue
            assert tag not in data
            #print(tag, value)
            if value != 'N/A':
                data[tag] = value
    for line in pusher:
        if line == '[FORMAT]':
            format()
    from datetime import timedelta
    attrs = {}
    if 'bit_rate' in data:
        attrs['bitrate'] = int(data['bit_rate'].rstrip('0').rstrip('.'))
    if 'duration' in data:
        attrs['duration'] = timedelta(seconds=float(data['duration']))
    return attrs

def main():
    from logging import basicConfig
    basicConfig(level=0)
    from subprocess import CalledProcessError
    from sys import argv
    from traceback import print_exc
    try:
        print(res_data(argv[1]))
    except CalledProcessError as exc:
        print_exc()
        print(exc.output)

if __name__ == '__main__':
    main()
