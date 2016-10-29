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

import os
import re
import ssl
import http.client


bundle_name_re = re.compile('^[0-9]{10}-[0-9]{10}.json.gz$')
bundle_name_extract_re = re.compile('^([0-9]{10})-([0-9]{10}).json.gz$')


def path_from_urlpath(urlpath):
    return urlpath.strip('/').split('/')


def build_bundle_filename(start, end):
    return '{:010}-{:010}.json.gz'.format(start, end)


def build_package_name(i):
    return '{:03}'.format(i)


def build_log_name(dnsname, path):
    return '_'.join([dnsname] + path)


def build_package_dir(pkg_root_dir, index, package_size, bundle_size):
    pkg_num = index // (package_size * bundle_size)
    return os.path.join(
        pkg_root_dir,
        build_package_name(pkg_num)
    )


def build_package_root_dir(root_dir, dnsname, path):
    log_name = build_log_name(dnsname, path)
    return os.path.join(root_dir, log_name)


def get_bundle_list(path, tree_size):
    """ get_bundle_list returns the (sorted) list of bundles in a directory. Only bundles are listed and if multiple
    bundles exist for a same starting index, only the "most complete" bundle is returned. That is that if a bundle goes
    from the entry 1024 to the entry 1200, another goes from 1024 to 2040 and another goes from 1024 to 2047, only the
    last one will be added to the list of bundles.

    :param path: the directory path containing the bundles
    :return: the list of bundles
    """

    global bundle_name_re
    global bundle_name_extract_re

    l = os.listdir(path)
    bundle_list = sorted([
        f
        for f in l
        if bundle_name_re.match(f)
    ])

    # Now we will filter that bundle list
    # We take advantage of the fact that bundles are named after the index of the first entry to "deduplicate".
    filtered_bundle_list = []
    bundle_list_len = len(bundle_list)
    for i in range(0, bundle_list_len):
        cur_info = bundle_name_extract_re.match(bundle_list[i])
        if i+1 < bundle_list_len:
            nxt_info = bundle_name_extract_re.match(bundle_list[i+1])
            if cur_info.group(1) == nxt_info.group(1) and int(nxt_info.group(2)) < tree_size:
                continue
        filtered_bundle_list.append(bundle_list[i])

    return filtered_bundle_list


def parse_url(url):
    pos = url.find('/')

    if pos < 0 or pos == len(url) - 1:
        return url, []
    dnsname = url[:pos]
    path = path_from_urlpath(url[pos:])
    return dnsname, path


def build_sth_name(tree_size):
    return 'sth-{:010}.json'.format(tree_size)


def build_info_file_name(pkg_num, tree_size):
    return '{:03}-{:010}.info'.format(pkg_num, tree_size)


def build_torrent_name(url, pkg_num, tree_size):
    dnsname, path = parse_url(url)
    log_name = build_log_name(dnsname, path)
    return '{}_{}-{:010}.torrent'.format(log_name, build_package_name(pkg_num), tree_size)


def build_magnet_name(url, pkg_num, tree_size):
    dnsname, path = parse_url(url)
    log_name = build_log_name(dnsname, path)
    return '{}_{}-{:010}.magnet'.format(log_name, build_package_name(pkg_num), tree_size)


def create_new_https_connection(dnsname):
    sslctx = ssl.create_default_context()
    sslctx.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:'
        'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSAAES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:'
        'ECDHE-RSAAES128-SHA256:ECDHE-ECDSA-CAMELLIA256-SHA384:ECDHE-RSA-CAMELLIA256-SHA384:'
        'ECDHE-ECDSA-CAMELLIA128-SHA256:ECDHE-RSA-CAMELLIA128-SHA256:DHE-RSA-AES256-GCM-SHA384:'
        'DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:AES256-GCM-SHA384:AES128-GCM-SHA256:'
        'AES256-SHA256:AES128-SHA256:CAMELLIA128-SHA256')
    return http.client.HTTPSConnection(dnsname, timeout=30, context=sslctx)

def build_urlpath(path, cmd, params=None):
    urlpath = []
    if not isinstance(path, type(None)) and len(path) > 0:
        urlpath = ['/'] + path
    urlpath.append('/ct/v1/')
    urlpath.append(cmd)
    if not isinstance(params, type(None)):
        urlpath.append('?')
        urlpath.append(params)
    return ''.join(urlpath)