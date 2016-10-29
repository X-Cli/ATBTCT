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

import gzip
import json
import urllib.parse
import os
import time
import math
import re
import base64
import struct
import cryptography
import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.asymmetric.padding
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.backends

from atbtct.utils import (
  build_bundle_filename, build_package_dir, bundle_name_re,
  bundle_name_extract_re, parse_url, build_sth_name, create_new_https_connection, build_urlpath
)

package_name_re = re.compile('^[0-9]{3}$')


def write_sth(log_dir, sth):
    """write_sth writes a sth Python object on disk

    :param log_dir: the directory to write the STH file to
    :param sth: the STH to write
    :return: None
    """
    filename = build_sth_name(sth['tree_size'])
    file_path = os.path.join(log_dir, filename)
    with open(file_path, 'wb') as fd:
        fd.write(bytes(json.dumps(sth), 'UTF-8'))


def get_public_key(pk):
    """ get_public_key returns a python-cryptography public key object instance from the base64 string parameter

    :param pk:the string representing the public key
    :return: the public key object instance
    """
    return cryptography.hazmat.primitives.serialization.load_der_public_key(
      base64.b64decode(bytes(pk, 'UTF-8')), backend=cryptography.hazmat.backends.default_backend()
    )


def get_verifier(pk, ths):
    """ get_verifier returns a python-cryptography verifier instance, initialized with the tree_head_signature value
    from the returned STH.

    :param pk: the python-cryptography public key object used to generate the verifier
    :param ths: the base64 string from the STH
    :return: returns a python-cryptography verifier instance
    """

    # Check sig format (hash_type, sig_type, len, signature)
    bths = base64.b64decode(bytes(ths, 'UTF-8'))
    hash_algo, sig_algo, sig_len = struct.unpack('>BBH', bths[:4])
    sig = bths[4:]

    # Check algo and length
    # "3" and "4" identifiers come from
    # https://github.com/google/certificate-transparency/blob/master/python/ct/proto/client.proto
    # DigitallySigned message
    if hash_algo != 4 or (sig_algo != 3 and sig_algo != 1) or sig_len != len(sig):
        raise Exception('Invalid signature format or not yet implemented algorithm')

    # Create verifier
    if sig_algo == 1:
        # RSA
        return pk.verifier(
            sig,
            cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15(),
            cryptography.hazmat.primitives.hashes.SHA256()
        )
    elif sig_algo == 3:
        return pk.verifier(
            sig,
            cryptography.hazmat.primitives.asymmetric.ec.ECDSA(cryptography.hazmat.primitives.hashes.SHA256())
        )
    raise Exception('Never reached')


def build_verified_data(obj):
    """ build_verified_data build the structure "digitally-signed TreeHeadSignature" from RFC6962 with the data from
    the STH object

    :param: the Python Object of the STH returned by the lo
    :return: byte string representation of a TreeHeadSignature
    """
    # 0 corresponds to Certificate Transparency v1 and 1 to "Tree_head"
    return struct.pack(
        '>BBQQ32s', 0, 1, obj['timestamp'], obj['tree_size'], base64.b64decode(bytes(obj['sha256_root_hash'], 'UTF-8'))
    )


def verify_sth(log_list_file, url, obj):
    """ verify_sth checks that the sha256_root_hash value is authentic using the public key in log_list.json from
    certificate-transparency.org. The verification of log_list.json authenticity is left to the caller of this function

    :param log_list_file: the log_list.json file from certificate-transparency.org
    :param url: the url of the log that returned the STH to verify
    :param obj: the STH as a Python Object
    :return: returns True if the STH is verified or throws an Invalid Signature exception (from python-cryptography)
    """

    # First, we get the public key of the log from the log_list file
    with open(log_list_file, 'rb') as fd:
        s = fd.read()
    log_obj = json.loads(s.decode('UTF-8'))

    for log in log_obj['logs']:
        if log['url'] == url:
            break
    else:
        raise Exception(
          'Log unknown: public key cannot be retrieved; cannot check STH validity'
        )

    # We now get the python-cryptography public key from the base64 string representation
    pk = get_public_key(log['key'])

    # We create a python-cryptography verifier instance based on the signature from the STH
    ver = get_verifier(pk, obj['tree_head_signature'])
    # We add to the verifier the data to verify, structured as documented in RFC6962 par3.5
    ver.update(build_verified_data(obj))

    # The following statement may raise an InvalidSignature exception!
    return ver.verify()


def get_sth(url):
    """ get_sth fetches a STH from a log and returns the Python object of the JSON response from the log

    :param url:
    :return: the Python object representing the log JSON response
    """
    dnsname, path = parse_url(url)
    c = create_new_https_connection(dnsname)
    c.request('GET', build_urlpath(path, 'get-sth'))
    r = c.getresponse()
    status = r.status
    s = r.read()
    if status != 200:
        raise Exception('Could not fetch STH')
    o = json.loads(s.decode('UTF-8'))
    c.close()

    return o


def get_entries(url, start, step_size, tree_size):
    """ get_entries acts as an iterator, querying the log until all entries are fetched from start to tree_size.

    :param url: the url of the log to query
    :param start: the index of the first entry to query (0-based)
    :param step_size: the number of entries to attempt to fetch per request
    :param tree_size: the maximum number of entries there is to fetch (if start is 0 and tree_size is 1, there is only
    one entry to fetch. If start is 1 and tree_size is 1, there is no entry to fetch because we are asking past the size
    of the tree.
    :return: yields up to step_size entries per "next()" call
    """
    dnsname, path = parse_url(url)
    s = None
    c = create_new_https_connection(dnsname)
    for i in range(start, tree_size, step_size):
        status = None
        while status != 200:
            try:
                end = min(i + step_size - 1, tree_size - 1)

                print('{}: Index: {}, End: {}; Treesize: {}'.format(time.ctime(), i, end, tree_size))
                c.request(
                    'GET', build_urlpath(path, 'get-entries', urllib.parse.urlencode({'start': i, 'end': end}))
                )

                r = c.getresponse()
                status = r.status
                s = r.read()

                if status != 200:
                    time.sleep(2)
            except Exception as e:
                print(e)
                status = None
                c = create_new_https_connection(dnsname)
                time.sleep(2)
        if not isinstance(s, type(None)):
            yield s


def detect_step_size(url, step_size):
    """ detect_step_size returns the minimum value between step_size and greatest power of two inferior to the maximum
    number of entries that the log is willing to return.

    :param url: the url of the log for which we want to detect the step_size
    :param step_size: the step_size we would want to use
    :return: the minimum value between step_size and greatest power of two inferior to the maximum
    number of entries that the log is willing to return.
    """
    s = next(iter(get_entries(url, 0, step_size, step_size)))
    o = json.loads(s.decode('UTF-8'))
    entries_count = len(o['entries'])
    return 1 << int(math.log(entries_count) // math.log(2))


def write_new_bundle(package_dir, bundle_start, bundle_lst):
    """ write_new_bundle writes a bundle down into the provided directory (assumed to be the correct package directory
    :)). The filename is based on the index of the first and the last entry index that are stored in it.

    :param package_dir: the directory to write the bundle into
    :param bundle_start: index of the first entry in the bundle
    :param bundle_lst: the list of bundle to insert into the new bundle file
    """

    try:
        os.stat(package_dir)
    except OSError:
        os.mkdir(package_dir)

    # Compute the index of the last entry in the bundle to name the bundle appropriately
    bundle_end = bundle_start + len(bundle_lst) - 1
    new_file = os.path.join(package_dir, build_bundle_filename(bundle_start, bundle_end))

    # Mimic the JSON dictionary that is returned by the logs so that it eases interoperability with potential third
    # party scripts
    bundles_to_write = {'entries': bundle_lst}

    print('Writing a new bundle: {}'.format(new_file))
    with gzip.open(new_file, 'w') as fd:
        fd.write(bytes(json.dumps(bundles_to_write), 'UTF-8'))


def handle_new_sth(sth, package_root_dir, log_list_file, url):
    """ handle_new_sth verifies the STH with the public key from the log_list and if the STH is valid, writes it down on
    disk in the package_root_dir

    :param sth: a STH, represented as the dict of the JSON answer from the log
    :param package_root_dir: the directory where are stored packages
    :param log_list_file: the list of logs, directly from certificate-transparency.org => known logs => log_list.json
    :param url: the full URL of the log that returned this STH, domain name and path included.
    :return None
    """
    # Verify_sth may raise exceptions. We let them bubble up
    verify_sth(log_list_file, url, sth)
    write_sth(package_root_dir, sth)


def get_ct(pkg_root_dir, url, log_list_file, start_index=0, step_size=1024, package_size=1024, bundle_size=1024):
    """ get_ct fetches from a log all entries from start_index to the last entry available from that log view.
    It writes down on disk the retrieved entries into the root_dir. Entries are organized in bundles of bundle_size
    entries and bundles are organized in package_size bundles. The step_size is the maximum number of entries that we
    *want* to fetch at once. It will not be necessarily be the actual number of entries that will be fetched with each
    query though.

    :param pkg_root_dir: directory where you want to store the packages of the log at "url"
    :param url: url of the log to query, domain name and path included
    :param log_list_file: the list of logs, directly from certificate-transparency.org => known logs => log_list.json
    :param start_index: (optional) the index of the first entry to query for (will be rounded down to the greatest
    bundle_size multiple inferior to the proposed start_index.
    :param step_size: the maximum number of entries we want to fetch per query
    :param package_size: the number of bundles in a package
    :param bundle_size: the number of entries in a bundle
    :return: Returns the new STH
    """

    # Verify that provided bundle_size is a power of two. This is required because we build binary trees per bundle and
    # the tree to be "complete".
    if not (bundle_size > 0 and ((bundle_size & (bundle_size - 1)) == 0)):
        raise Exception('bundle_size arg must be a power of 2')

    # Trying to create the package dir hierarchy on the filesystem; in case it does not exist yet
    try:
        os.mkdir(pkg_root_dir)
    except OSError:
        pass

    # We get the STH from the log server
    sth = get_sth(url)
    handle_new_sth(sth, pkg_root_dir, log_list_file, url)

    if start_index >= 0 and start_index >= sth['tree_size']:
        raise Exception('Nothing to do. You already have the whole tree that can be fetched from this log (view).')

    # All logs do not return the requested number of entries; we detect the returned number of entries, and we round it
    # down to the greatest power of 2, inferior to the number of entries returned.
    detected_step_size = detect_step_size(url, step_size)
    if detected_step_size != step_size:
        print("New step size defined: {}".format(detected_step_size))
        step_size = detected_step_size

    # Rounding to bundle_size multiple
    start_index = (start_index // bundle_size) * bundle_size
    bundle_start = start_index

    # Fetching the entries!
    bundle_lst = []
    for s in get_entries(url, start_index, step_size, sth['tree_size']):
        new_entries = json.loads(s.decode('UTF-8'))['entries']
        bundle_lst += new_entries
        # If the number of accumulated entries raises over the bundle_size, we write down bundle_size entries to disk
        if len(bundle_lst) >= bundle_size:
            write_new_bundle(
                build_package_dir(pkg_root_dir, bundle_start, package_size, bundle_size),
                bundle_start, bundle_lst[:bundle_size]
            )
            bundle_lst = bundle_lst[bundle_size:]
            bundle_start += bundle_size
    # We perform a last write order to put on disk the remaining entries after we reached the last of the available
    # entries
    if len(bundle_lst) > 0:
        write_new_bundle(
            build_package_dir(pkg_root_dir, bundle_start, package_size, bundle_size),
            bundle_start, bundle_lst
        )
    return sth


def discover_start_index(package_root_dir, package_size, bundle_size):
    """discover_start_index returns the index of the first entry index of the last bundle of the last package
    If we find an empty last package, we infer this index from the package name. If no packages are found, the index
    is 0

    :param package_root_dir: the directory containing the packages. Used to hunt for packages
    :param package_size: the number of bundles in a package
    :param bundle_size: the number of entries in a bundle
    :return: The index of the first entry to query
    """
    global package_name_re
    global bundle_name_re
    global bundle_name_extract_re

    # We fetch the list of packages in the package_root_dir
    try:
        package_list = sorted([
            dir_name
            for dir_name in os.listdir(package_root_dir)
            if package_name_re.match(dir_name)
        ])
    except OSError:
        return 0

    if len(package_list) == 0:
        return 0

    last_package_dir = os.path.join(package_root_dir, package_list[-1])

    # We fetch the list of bundles in the last package
    bundle_list = sorted([
        bundle_name
        for bundle_name in os.listdir(last_package_dir)
        if bundle_name_re.match(bundle_name)
    ])
    if len(bundle_list) == 0:
        # Empty package directory; we infer the index of the first bundle from the package dir name, which is supposed
        # to be of the form something/.../something/number that we multiply by the number of entries per package dir
        return int(package_root_dir.split(os.sep)[-1]) * package_size * bundle_size

    # We keep the last bundle
    last_bundle = bundle_list[-1]

    # Extract bundle info from bundle name
    match_res = bundle_name_extract_re.match(last_bundle)
    bundle_start = int(match_res.group(1))
    bundle_end = int(match_res.group(2))

    if bundle_end - bundle_start + 1 == bundle_size:
        # Last bundle is already complete. Starting a new one
        return bundle_end + 1
    # Refetch the last bundle, which was incomplete
    return bundle_start
