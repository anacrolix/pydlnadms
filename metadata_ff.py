#!/usr/bin/env python3

def res_data(path):
    from subprocess import Popen, PIPE, CalledProcessError, list2cmdline
    def preexec_fn():
        from resource import setrlimit, RLIMIT_CPU
        # give the process 1 second, 2 if it treats SIGXCPU
        setrlimit(RLIMIT_CPU, (1, 2))
    args = ['ffprobe', '-show_format', path]
    p = Popen(
        args,
        stdout=PIPE,
        stderr=PIPE,
        preexec_fn=preexec_fn,
        close_fds=True)
    stdout, stderr = p.communicate()
    from logging import getLogger
    logger = getLogger()
    if p.wait() != 0:
        logger.warning('{!r} failed with exit code {:d}'.format(
            list2cmdline(args),
            p.returncode))
        return {}
    pusher = (l.rstrip() for l in stdout.decode('utf-8').splitlines())
    data = {}
    def format():
        for line in pusher:
            if line == '[/FORMAT]':
                return
            tag, value = map(str.strip, line.split('=', 1))
            assert tag not in data
            print(tag, value)
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
