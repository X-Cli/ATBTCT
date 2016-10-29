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
import json
import re
import gzip
import base64
import math
import multiprocessing
import hashlib

from atbtct.utils import build_package_name, get_bundle_list, build_info_file_name


bundle_name_re = re.compile('^[0-9]{10}-[0-9]{10}.json.gz$')
hash_name_re = re.compile('^[0-9]{3}-[0-9]{10}.info$')
hash_name_extract_re = re.compile('^([0-9]{3})-([0-9]{10}).info$')


def get_leaf_hashes(bundle_fn):
    """ get_leaf_hashes computes the hash of all entries in a bundle

    :param bundle_fn: the bundle filename whose entries are hashed
    :return: the list of hashes of all entries of the specified bundle
    """
    leaf_hashes = []
    with gzip.open(bundle_fn, 'rb') as fd:
        o = json.loads(fd.read().decode('UTF-8'))
        for entry in o['entries']:
            leaf = base64.b64decode(bytes(entry['leaf_input'], 'UTF-8'))
            h = hashlib.sha256()
            h.update(b'\x00')  # This magic 0 is from RFC6962; its purpose is domain separation
            h.update(leaf)
            leaf_hashes.append(h.digest())
    return leaf_hashes


def get_partial_tree_hash(entry_hashes):
    """ get_partial_tree_hash computes the Merkle Tree root of the hash list it receives as parameter

    :param entry_hashes: a list of "stuff" (package hashes or leaf hashes most probably) to hash together
    :return: the Merkle Tree root hash
    """
    cur = entry_hashes
    new = []
    clen = len(cur)
    while clen != 1:
        max_loop = clen if clen % 2 == 0 else (clen - 1)
        for i in range(0, max_loop, 2):
            # h = cryptography.hazmat.primitives.hashes.Hash(
            #     algorithm=cryptography.hazmat.primitives.hashes.SHA256(),
            #     backend=cryptography.hazmat.backends.default_backend()
            # )
            h = hashlib.sha256()
            h.update(b'\x01')
            h.update(cur[i])
            h.update(cur[i+1])
            new.append(h.digest())
        # If the number of entries is odd, the last element, which was not hashed,
        # is carried over to the new hash list
        if clen % 2 == 1:
            new.append(cur[-1])
        cur = new
        new = []
        clen = len(cur)
    return cur[0]


def write_tree_hash(pkg_root_dir, pkg_num, tree_size, root_hash):
    """ write_tree_hash writes down on disk the "info file" of a package. This file contains the merkle tree root hash
    of a package in formatted in JSON.
    The filename is dependent of the tree_size because the root hash of "incomplete" packages vary as more entries are
    added to the log.

    :param pkg_root_dir: the directory containing the packages
    :param pkg_num: the number of the package that was hashed
    :param tree_size: the log's merkle tree size
    :param root_hash: the Merkle Tree root hash of the package
    :return: None
    """
    filename = build_info_file_name(pkg_num, tree_size)
    file_path = os.path.join(pkg_root_dir, filename)

    # The merkle_proof list that is empty in the following dictionary is filled later on by another function when the
    # "global" root hash of all packages is computed
    info = {'pkg_hash': base64.b64encode(root_hash).decode('UTF-8'), 'merkle_proof': []}

    bs = bytes(json.dumps(info), 'UTF-8')

    with open(file_path, 'wb') as fd:
        fd.write(bs)


def get_pkg_hash_list(pkg_root_dir, tree_size):
    """ get_pkg_hash_list reads all info files of a log, keeps only the most recent ones that are part of a tree of
    tree_size entries and returns the "pkg_hash" of all of these info files.

    :param pkg_root_dir: the directory containing all packages from a log
    :param tree_size: the tree_size up to which the hashes must be fetched
    :return: the list of hashes of every packages of interest
    """

    global hash_name_re
    global hash_name_extract_re

    # Get all the info files in the log dir
    l = os.listdir(pkg_root_dir)
    info_file_list = sorted([
        f
        for f in l
        if hash_name_re.match(f)
    ])

    # Filter this list so that we keep only the most recent one that are not newer than tree_size
    filtered_info_file_lst = []
    lst_len = len(info_file_list)
    for i in range(0, lst_len):
        cur_ids = hash_name_extract_re.match(info_file_list[i])
        if i < lst_len - 1:
            nxt_ids = hash_name_extract_re.match(info_file_list[i+1])
            if (
                cur_ids.group(1) == nxt_ids.group(1)
                and int(nxt_ids.group(2)) <= tree_size
            ):
                # Next info file is about the same package and it is more recent while not too much recent; let's skip
                # this one
                continue
        if int(cur_ids.group(2)) <= tree_size:
            filtered_info_file_lst.append(info_file_list[i])

    # Get the package hash value from the remaining files!
    hash_list = []
    for hash_file in filtered_info_file_lst:
        with open(os.path.join(pkg_root_dir, hash_file), 'rb') as fd:
            o = json.loads(fd.read().decode('UTF-8'))
            hash_list.append(base64.b64decode(o['pkg_hash']))
    return hash_list


def write_proof(pkg_root_dir, tree_size, pkg_num, proof_list):
    """ write_proof writes down on disk into the package info file the inclusion proof of the subtree of that package
    into the STH.

    :param pkg_root_dir: the directory containing the packages
    :param tree_size: the first fetched tree size that provides enough entries to complete the package. If the package
    is incomplete, the tree_size that comes the closest.
    :param pkg_num: the package number whose proof was computed
    :param proof_list: the proof list
    :return: None
    """

    filename = build_info_file_name(pkg_num, tree_size)
    file_path = os.path.join(pkg_root_dir, filename)

    with open(file_path, 'rb') as fd:
        o = json.loads(fd.read().decode('UTF-8'))

    o['merkle_proof'] = [
        base64.b64encode(proof).decode('UTF-8')
        for proof in proof_list
    ]

    with open(file_path, 'wb') as fd:
        fd.write(bytes(json.dumps(o), 'UTF-8'))


def compute_proofs(pkg_root_dir, tree_size, start_package, last_package):
    """ compute_proofs computes the Merkle Tree Root from the package hashes. It updates the info file from
    start_package to last_package with a proof of inclusion of that package into the tree of tree_size entries

    :param pkg_root_dir: the directory containing the packages
    :param tree_size: the number of entries into the tree that we are computing the root hash for
    :param start_package: the first package whose info file must be updated with a proof of inclusion
    :param last_package: the last package whose info file must be updated with a proof of inclusion
    :return:
    """
    # Get all the hashes from every packages. Get the hash from the most recent info file that is in the limits of a
    # tree of tree_size entries
    hash_list = get_pkg_hash_list(pkg_root_dir, tree_size)
    numbered_hash_list = list(enumerate(hash_list))

    # Initialisation of the structure that will hold the proofs
    proofs = {}
    for i in range(start_package, last_package + 1):
        proofs[i] = []

    # The mask is used to compare most significant bits in common in the packages
    # of interest and the current branch that is hashed
    if last_package > 0:
        mask = (1 << int(math.ceil(math.log(last_package) / math.log(2)))) - 1
    else:
        mask = 1
    # The mask canceler is used to perform evolution over the mask as the journey
    # from the leaf toward the tree root is made in order to compute tree root
    # hash. The mask canceler is also used to decide which branch to insert into
    # the proofs of each packages
    mask_canceler = 1
    cur = numbered_hash_list
    new = []
    cur_len = len(cur)
    while cur_len > 1:
        # The mask is updated to zeroize the LSB that is set; this allows comparision of "prefixes" (much like a network
        # mask)
        mask ^= mask_canceler

        # We hash together elements of the Merkle tree, two by two; there is no room for a single element; this last
        # single element is kept for later use and will not be hashed within this loop
        max_loop = cur_len if cur_len % 2 == 0 else (cur_len - 1)
        for i in range(0, max_loop, 2):
            # Before hashing two elements, we take note of the ones that are relevant for inclusion proofs
            for pkg_num in proofs.keys():
                if pkg_num & mask == cur[i][0] & mask:
                    if pkg_num & mask_canceler != 0:
                        proofs[pkg_num].append(cur[i][1])
                    else:
                        proofs[pkg_num].append(cur[i+1][1])
            # Hashing the two elements together
            h = hashlib.sha256()
            h.update(b'\x01')
            h.update(cur[i][1])
            h.update(cur[i+1][1])
            dgst = h.digest()
            new.append((cur[i][0] & mask, dgst))

        # If the number of entries is odd, the last element, which was not hashed,
        # is carried over to the new hash list
        if cur_len % 2 == 1:
            new.append(cur[-1])

        # Generating new run
        mask_canceler <<= 1
        cur = new
        new = []
        cur_len = len(cur)

    # Update all info file for the packages that need inclusion proofs
    for pkg_num, proof_list in proofs.items():
        write_proof(pkg_root_dir, tree_size, pkg_num, proof_list)

    # Return the tree root hash
    return base64.b64encode(cur[0][1])


def compute_package(args):
    """ compute_package hashes a package and writes the result into a info hash file

    :param args: tuple containing the package number, the directory containing the packages and the tree_size
    :return:
    """
    (pkg_num, log_dir, tree_size) = args

    print('Computing package {}'.format(pkg_num))

    package_dir = os.path.join(log_dir, build_package_name(pkg_num))

    bundle_list = get_bundle_list(package_dir, tree_size)

    # Computes the hash of each bundle
    partial_tree_hash_list = []
    for bndl in bundle_list:
        bndl_path = os.path.join(package_dir, bndl)
        leaf_hashes = get_leaf_hashes(bndl_path)
        partial_tree_hash_list.append(get_partial_tree_hash(leaf_hashes))

    # Compute the hash of the package from the list of bundles
    tree_hash = get_partial_tree_hash(partial_tree_hash_list)
    write_tree_hash(log_dir, pkg_num, tree_size, tree_hash)


def compute_packages(log_dir, start_package, last_package, tree_size, workers=None):
    """ compute_packages computes the hashes of all packages between start_package and last_package
    Tree_size is used to name the info hash file.

    :param log_dir: The directory of containing the packages to hash
    :param start_package: the first package to hash
    :param last_package: the last package to hash
    :param tree_size: the tree_size; used to name the info hash files
    :param workers: the number of workers that will proceed
    :return: None
    """
    p = multiprocessing.Pool(workers)
    params = [
        (i, log_dir, tree_size)
        for i in range(start_package, last_package + 1)
    ]
    p.map(compute_package, params)
    p.terminate()
    p.join()
