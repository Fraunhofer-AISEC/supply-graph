#!/usr/bin/env python3
import select
import time

import pyfanotify as fan


src_dir = '/home/tobias/Downloads/sca-training/src/dilithium'


def foo(t):
    print('calling `foo` every %s seconds' % t)


if __name__ == '__main__':
    foo_timeout = 1
    fanot = fan.Fanotify(fn=foo, fn_args=(foo_timeout,), fn_timeout=foo_timeout)
    fanot.mark(src_dir, is_type='mp', ev_types=fan.FAN_OPEN_PERM)
    fanot.start()

    cli = fan.FanotifyClient(fanot, path_pattern=f'{src_dir}/*')
    poll = select.poll()
    poll.register(cli.sock.fileno(), select.POLLIN)
    try:
        while poll.poll():
            x = {}
            for i in cli.get_events():
                time.sleep(60)
                i.ev_types = fan.evt_to_str(i.ev_types)
                x.setdefault(i.path, []).append(i)
                if 'close_nowrite' in i.ev_types:
                    print(f'read: {i.path}')
                    time.sleep(60)
                elif 'close_write' in i.ev_types:
                    print(f'write: {i.path}')
                    time.sleep(60)
    except:
        print('STOP')

    cli.close()
    fanot.stop()