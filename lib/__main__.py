#!/usr/bin/env python3
# filetype=python3

import os, os.path

def main():
    from optparse import OptionParser
    parser = OptionParser(
        usage='%prog [options] [PATH]',
        description='Serves media from the given PATH over UPnP AV and DLNA.')
    parser.add_option(
        '-p', '--port', type='int', default=1337,
        help='media server listen PORT')
    parser.add_option(
        '--logging-conf',
        help='Path of Python logging configuration file')
    opts, args = parser.parse_args()

    import logging, logging.config
    if opts.logging_conf is None:
        formatter = logging.Formatter(
            '%(asctime)s.%(msecs)3d;%(levelname)s;%(name)s;%(message)s',
            datefmt='%H:%M:%S')
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        logger.addHandler(handler)
    else:
        logging.config.fileConfig(opts.logging_conf)
    logger = logging.getLogger('pydlnadms.main')
    logger.debug('Parsed opts=%r args=%r', opts, args)
    del logging

    if len(args) == 0:
        path = os.curdir
    elif len(args) == 1:
        path = args[0]
    else:
        parser.error('Only one path is allowed')
    path = os.path.normpath(path)

    # import this AFTER logging config has been processed
    from pydlnadms import DigitalMediaServer
    DigitalMediaServer(opts.port, path)

if __name__ == '__main__':
    main()

