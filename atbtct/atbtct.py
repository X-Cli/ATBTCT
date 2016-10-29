#!/usr/bin/env python3
# MIT License
#
# Copyright (c) 2016 Florian Maury
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


import argparse
import os
import configparser

import atbtct.getct
import atbtct.hashbundles
import atbtct.bittorrent
import atbtct.utils

# DO NOT ALTER THESE THREE VALUES UNLESS YOU KNOW WHAT
# YOU ARE DOING AND YOU UNDERSTAND THAT A WRONG VALUE
# MAY GENERATE INVALID RESULTS!
package_size = 1024
bundle_size = 1024
step_size = 1024


def check_args(log_list, root_dir, torrent_dir):
    if not os.access(log_list, os.R_OK):
        raise Exception('Log list file cannot be read. Check permissions.')
    if not os.access(root_dir, os.R_OK | os.W_OK):
        raise Exception('Root directory is not RW. Check permissions.')
    if not os.access(torrent_dir, os.R_OK | os.W_OK):
        raise Exception('Torrent directory is not RW. Check permissions.')


def process_log(log_list, root_dir, torrent_dir, url, download_url, trackers, peers, suggested_name, asn, workers):
    global package_size
    global bundle_size
    global step_size

    if isinstance(suggested_name, type(None)):
        dns_name, path = atbtct.utils.parse_url(url)
        pkg_root_dir = atbtct.utils.build_package_root_dir(root_dir, dns_name, path)
    else:
        pkg_root_dir = os.path.join(root_dir, suggested_name)

    start_index = atbtct.getct.discover_start_index(pkg_root_dir, package_size, bundle_size)

    sth = atbtct.getct.get_ct(
        pkg_root_dir, url, log_list, start_index, package_size=package_size, bundle_size=bundle_size
    )

    start_package = start_index // (bundle_size * package_size)
    # We need to reduce by one, because entry indexes are 0-based
    last_package = (sth['tree_size'] - 1) // (bundle_size * package_size)

    atbtct.hashbundles.compute_packages(pkg_root_dir, start_package, last_package, sth['tree_size'], workers)

    computed_tree_root_hash = atbtct.hashbundles.compute_proofs(
        pkg_root_dir, sth['tree_size'], start_package, last_package
    )

    if computed_tree_root_hash != bytes(sth['sha256_root_hash'], 'UTF-8'):
        raise Exception('Invalid Entries obtained while processing from entry {} to entry {}'.format(
                start_index, sth['tree_size']
            )
        )

    atbtct.bittorrent.create_torrents(
        torrent_dir, pkg_root_dir,
        url, download_url,
        start_package, last_package,
        sth['tree_size'],
        trackers, peers,
        suggested_name, asn,
        workers
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', action='store', dest='config_file', required=True,
                        help='Path of the file containing most of the configuration options.'
                        )
    parser.add_argument('-u', '--url', action='store', dest='url', required=True,
                        help='Specify the one log to operate on.')
    parser.add_argument('-n', '--name', action='store', dest='suggested_name',
                        help='Name to use to refer to this log archive, in various places in this script. Better left unspecified in most cases.'
                        )

    subparsers = parser.add_subparsers(dest='action')
    subparsers.add_parser('auto')

    getct_parser = subparsers.add_parser('expert_getct')
    getct_parser.add_argument('-s', '--start', type=int, dest='start_index', default=0,
                              help='Index of the first entry to fetch (will be rounded down to the greatest multiple of bundle_size inferior or equal to the provided value'
                              )
    getct_parser.add_argument('-S', '--step', type=int, dest='step_size', default=10,
                              help='Power of two of the number of entries to fetch; x for pow(2,x) entries to be fetched'
                              )
    getct_parser.add_argument('-b', '--bundle', type=int, dest='bundle_size', default=10,
                              help='Power of two of the number of entries in a bundle; x for pow(2,x) entries in a single bundle'
                              )
    getct_parser.add_argument('-p', '--package', type=int, dest='package_size', default=10,
                              help='Power of two of the number of bundles in a package; x for pow(2,x) bundles in a single package'
                              )

    hash_parser = subparsers.add_parser('expert_hash')
    hash_parser.add_argument('-s', '--start', type=int, dest='start_package', default=0,
                             help='Number of the first package to hash')
    hash_parser.add_argument('-e', '--end', type=int, dest='last_package', default=0,
                             help='Number of the last package to hash')
    hash_parser.add_argument('-t', '--treesize', type=int, dest='tree_size', default=0,
                             help='Tree_size (used to name the hash info file and to determine the last entry to hash for incomplete packages)'
                             )

    bt_parser = subparsers.add_parser('expert_bt')
    bt_parser.add_argument('-s', '--start', type=int, dest='start_package', default=0,
                           help='Number of the first package for which to create a torrent'
                           )
    bt_parser.add_argument('-e', '--end', type=int, dest='last_package', default=0,
                           help='Number of the last package for which to create a torrent'
                           )
    bt_parser.add_argument('-t', '--treesize', type=int, dest='tree_size', default=0,
                           help='Tree_size (used to name the torrent files and to determine the last entry to put in a torrent for incomplete packages)'
                           )

    args = parser.parse_args()

    try:
        config = configparser.ConfigParser()
        config.read(args.config_file)
    except configparser.Error as e:
        print('Error while opening the configuration file: {}'.format(e))
        return

    try:
        log_list_file = config.get('General', 'log_list_file')
    except configparser.NoSectionError:
        print('General section is missing from the config file!')
        return
    except configparser.NoOptionError:
        print('Mandatory item "General.log_list_file" is missing from config file')
        return

    try:
        download_url = config.get('General', 'download_url')
    except configparser.NoOptionError:
        print('Mandatory item "General.download_url" is missing from config file')
        return

    try:
        root_dir = config.get('General', 'root_dir')
    except configparser.NoOptionError:
        root_dir = '/tmp'

    try:
        torrent_dir = config.get('General', 'torrent_dir')
    except configparser.NoOptionError:
        torrent_dir = '/tmp'

    try:
        asn = config.get('General', 'ASN')
    except configparser.NoOptionError:
        asn = None

    try:
        workers = int(config.get('General', 'workers'))
    except (ValueError, configparser.NoOptionError):
        workers = None

    try:
        trackers = list(config['Trackers'].values())
    except (KeyError, configparser.NoSectionError):
        trackers = []

    try:
        peers = list(config['Peers'].values())
    except (KeyError, configparser.NoSectionError):
        peers = []

    check_args(log_list_file, root_dir, torrent_dir)

    if isinstance(args.suggested_name, type(None)):
        dns_name, path = atbtct.utils.parse_url(args.url)
        suggested_name = atbtct.utils.build_log_name(dns_name, path)
    else:
        suggested_name = args.suggested_name


    if args.action == 'auto' or isinstance(args.action, type(None)):
        process_log(
            log_list_file,
            root_dir, torrent_dir,
            args.url, download_url,
            trackers, peers,
            suggested_name, asn,
            workers
        )
    else:
        if isinstance(args.suggested_name, type(None)):
            dns_name, path = atbtct.utils.parse_url(args.url)
            pkg_root_dir = atbtct.utils.build_package_root_dir(root_dir, dns_name, path)
        else:
            pkg_root_dir = os.path.join(root_dir, args.suggested_name)

        if args.action == 'expert_getct':
            atbtct.getct.get_ct(pkg_root_dir, args.url, log_list_file, args.start_index,
                                1 << args.step_size, 1 << args.package_size, 1 << args.bundle_size
                                )

        elif args.action == 'expert_hash':
            atbtct.hashbundles.compute_packages(
                pkg_root_dir, args.start_package, args.last_package, args.tree_size, workers)

            computed_tree_root_hash = atbtct.hashbundles.compute_proofs(
                pkg_root_dir, args.tree_size, args.start_package, args.last_package
            )
            print('Computed Tree Root Hash: {}'.format(computed_tree_root_hash))
        elif args.action == 'expert_bt':
            atbtct.bittorrent.create_torrents(
                torrent_dir, pkg_root_dir,
                args.url, download_url,
                args.start_package, args.last_package,
                args.tree_size,
                trackers, peers,
                suggested_name, asn,
                workers
            )
        else:
            raise Exception('Never reached')

if __name__ == '__main__':
    main()
