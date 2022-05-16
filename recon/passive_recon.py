#!/usr/bin/python3

import sys
import subprocess
import os
import argparse
import shutil

# apt install amass massdns
# go install -v github.com/s0md3v/smap/cmd/smap@latest
# set $PATH for go binaries


def run_amass(target):
    subprocess.run([
        'amass',
        'enum',
        '-passive',
        '-d', target,
        '-o', 'amass-'+target+'.txt'])


def run_massdns(target, resolvers):
    subprocess.run([
        'massdns',
        '-q',
        '-r', resolvers,
        '-t', 'A',
        '-o', 'S',
        '-w', 'massdns-'+target+'.txt',
        'amass-'+target+'.txt'])


def find_A_records(file, target):
    ips = []
    with open(file, 'r') as resolved:
        for line in resolved:
            if "A" in line.split():
                ips.append(line.split()[2])
    with open('resolved-'+target+'.txt', 'w') as A_records:
        for ip in ips:
            A_records.write(ip+'\n')


def run_smap(target, targets):
    subprocess.run([
        'smap',
        '-sV',
        '-iL', targets,
        '-oA', 'smap-'+target])


def check_dependencies():
    if shutil.which('amass') is None:
        print('Install amass "apt install amass"')
        exit(1)
    if shutil.which('massdns') is None:
        print('Install massdns "apt install massdns"')
        exit(1)
    if shutil.which('smap') is None:
        print('Install smap "go install -v github.com/s0md3v/smap/cmd/smap@latest"')
        exit(1)


def prepare_resolvers():
    with open('resolvers.txt', 'w') as resolvers:
        resolvers.write('1.0.0.1'+'\n')
        resolvers.write('8.8.8.8'+'\n')
        resolvers.write('208.67.220.222'+'\n')
        resolvers.write('198.82.247.34'+'\n')


def main(argv):
    parser = argparse.ArgumentParser(
        description="Perform basic recon using only passive techniques, tools: amass, massdns, smap")
    parser.add_argument('--domain', required=True,
                        help="domain for amass, example.com")
    parser.add_argument('--resolvers', required=False,
                        help="a file with resolvers in each line for massdns, optional")
    args = parser.parse_args()

    check_dependencies()

    if not args.resolvers:
        prepare_resolvers()
        resolvers = 'resolvers.txt'

    resolvers = args.resolvers

    if not os.path.isfile('amass-'+args.domain+'.txt'):
        run_amass(args.domain)
    if not os.path.isfile('massdns-'+args.domain+'.txt'):
        run_massdns(args.domain, resolvers)
    if os.path.isfile('massdns-'+args.domain+'.txt'):
        find_A_records('massdns-'+args.domain+'.txt', args.domain)
    if os.path.isfile('resolved-'+args.domain+'.txt'):
        run_smap(args.domain, 'resolved-'+args.domain+'.txt')


if __name__ == '__main__':
    main(sys.argv)
