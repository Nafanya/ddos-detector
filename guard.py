#!/usr/bin/env python3

import argparse
import random
import subprocess
from collections import Counter
import sys


# Shell escape codes
import time

BLACK = '\033[0;30m'
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[0;33m'
BLUE = '\033[0;34m'
WHITE = '\033[0;37m'
NO_COLOR = '\033[0m'

message = ''
added_rules = []

# Proto Recv-Q Send-Q Local Address           Foreign Address         State
# tcp        0      0 127.0.0.1:60832         127.0.0.1:8080          ESTABLISHED 19084/telnet



class ConnEntry:

    def __init__(self, line):
        t = line.split()
        self.local_addr, self.local_port = self.parse_addr_port(t[3])
        self.remote_addr, self.remote_port = self.parse_addr_port(t[4])
        self.state = t[5]
        self.proc = ' '.join(t[6:])

    def __repr__(self):
        return 'local address={}:{}, foreign address={}:{}, state:{} proc:{}'.format(
              self.local_addr, self.local_port,
              self.remote_addr, self.remote_port,
              self.state,
              self.proc)

    @staticmethod
    def parse_addr_port(addr):
        if addr.startswith('::'):
            return '::', addr[4:]
        return addr.split(':')


def gen_system_connections():
    servers = random.randint(3, 5)
    victims = random.randint(0, 2)



def get_system_connections(stub=True):
    if stub:
        with open('connections.data') as f:
            lines = f.readlines()
            conns = map(ConnEntry, lines)
            return list(conns)
    else:
        # netstat = subprocess.Popen(['sudo', 'netstat', '-plan'])
        # grep = subprocess.Popen(['grep', 'tcp'])
        b = subprocess.check_output('sudo netstat -n | grep tcp', shell=True)
        s = b.decode('utf-8')
        lines = s.splitlines()
        return list(map(ConnEntry, lines))


def get_attacks(connections, type, conn_threshold):
    conns = filter(lambda c: c.state == type, connections)
    addrs = map(lambda c: c.remote_addr + ':' + c.remote_port, conns)
    cnt = Counter(addrs)
    attacks = filter(lambda c: c[1] >= conn_threshold, cnt.items())
    return list(attacks)


def print_tick(est_attacks, syn_flood_attacks):
    global added_rules
    sys.stdout.write((' ' * 100 + '\n') * 100)
    sys.stdout.write(u"\u001b[1000D")  # Move left
    sys.stdout.write(u"\u001b[100A")  # Move up

    text = ''

    text += BLUE + '\t\tDDOS Attack Detector' + NO_COLOR + '\n\n'
    text += GREEN + 'Attacks blocked: {}\n'.format(len(added_rules))
    text += YELLOW + 'iptables rules added:\n' + '\n'.join(map(lambda x: '\t' + x, added_rules)) + NO_COLOR + '\n'
    text += YELLOW + message + NO_COLOR + '\n\n'
    if not est_attacks:
        text += (GREEN + 'No large amount of tcp connections attacks detected' + NO_COLOR + '\n')
    else:
        text += (RED + 'Large amount of tcp connections attacks detected' + NO_COLOR + '\n')
        text += ('Address             # of connections\n')
        for addr, cnt in est_attacks:
            text += (BLACK + addr + NO_COLOR + (' ' * (20 - len(addr))) + BLACK + str(cnt) + NO_COLOR + '\n')

    if not syn_flood_attacks:
        text += (GREEN + 'No SYN flood attacks detected' + NO_COLOR + '\n')
    else:
        text += (RED + 'SYN flood attack detected' + NO_COLOR + '\n')
        text += ('Address             # of connections\n')
        for addr, cnt in est_attacks:
            text += (BLACK + addr + NO_COLOR + (' ' * (20 - len(addr))) + BLACK + str(cnt) + NO_COLOR + '\n')

    sys.stdout.write(text)
    sys.stdout.write(u"\u001b[1000D")  # Move left
    sys.stdout.write(u"\u001b[{}A".format(text.count('\n')))  # Move up


def prevent_attack(demo, attacks):
    # print('prevent attacks', attacks)
    global added_rules
    for addr, cnt in attacks:
        a, p = ConnEntry.parse_addr_port(addr)
        cmd = '-A INPUT -s {ip} -p tcp --destination-port {port} -j DROP'.format(ip=a, port=p)
        if cmd not in added_rules:
            print(cmd)
            added_rules.append(cmd)
            if not demo:
                subprocess.check_output(['sudo', 'iptables'] + cmd.split(' '))


def remove_rules():
    global added_rules
    for rule in added_rules:
        cmd = rule.replace('-A', '-D')
        subprocess.check_output(['sudo', 'iptables'] + cmd.split(' '))


def main(demo, soft, hard):
    # sys.stdout.write('\033[2J')
    while True:
        try:
            conns = get_system_connections(demo)

            est_potential_attacks = get_attacks(conns, 'ESTABLISHED', soft)
            syn_flood_potential_attacks = get_attacks(conns, 'SYN_REC', soft)

            print_tick(est_potential_attacks, syn_flood_potential_attacks)

            est_attacks = get_attacks(conns, 'ESTABLISHED', hard)
            syn_flood_attacks = get_attacks(conns, 'SYN_REC', hard)

            prevent_attack(demo, est_attacks)
            prevent_attack(demo, syn_flood_attacks)

            time.sleep(0.5)
        except KeyboardInterrupt:
            sys.stdout.write('\033[K')
            if not demo:
                remove_rules()
            break


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SYN flood and large amount connection attacks detector')
    parser.add_argument('--demo', action='store_true')
    parser.add_argument('--soft-limit', default=10, type=int)
    parser.add_argument('--hard-limit', default=100, type=int)

    args = parser.parse_args()

    main(args.demo, args.soft_limit, args.hard_limit)