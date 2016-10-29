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
import hashlib
import multiprocessing
import json
import codecs
import xml.dom.minidom
import time

from atbtct.utils import (
    get_bundle_list, build_package_name, parse_url, build_sth_name, build_info_file_name,
    build_torrent_name, build_magnet_name, build_log_name
)


class EndDict(object):
    """ EndDict is just a symbol to detect the end of a dict in the bencode function
    """


class EndList(object):
    """ EndList is just a symbol to detect the end of a list in the bencode function
    """


class Raw(object):
    """ Raw is a simple class that contains a value and returns it. It is used in the bencode function to differentiate
    a bytes string from an already bencoded object (which happens to be a bytes array)"""
    def __init__(self, v):
        self._v = v

    def value(self):
        return self._v


def bencode(obj):
    """ bencode takes an "object" (dict, list of strings, int, bytes and Raw), and encodes it according to the
    BEP-0003 specification, which can be found on bittorrent.org

    :param obj: the "object" to encode
    :return: the bencoded representation of the provided object
    """

    l = [obj]
    s = []
    while len(l) > 0:
        item = l.pop(0)
        if isinstance(item, Raw):
            s.append(item.value())
        elif isinstance(item, (EndDict, EndList)):
            s.append(b'e')
        elif isinstance(item, bytes):
            s.append(bytes(str(len(item)), 'UTF-8') + b':' + item)
        elif isinstance(item, str):
            s.append(bytes('{}:{}'.format(len(item), item), 'UTF-8'))
        elif isinstance(item, int):
            s.append(b'i' + bytes(str(item), 'UTF-8') + b'e')
        elif isinstance(item, list):
            s.append(b'l')
            l = list(item) + [EndList()] + l
        elif isinstance(item, dict):
            s.append(b'd')
            new_l = []
            for k, v in sorted(item.items()):
                new_l += [k, v]
            l = new_l + [EndDict()] + l
    return b''.join(s)


def get_file_list(pkg_root_dir, pkg_num, tree_size):
    """ get_file_list walks a package directory and gets all bundles in it, up to a specified tree_size. It returns
    a list of dict to fit in the "files" property of a bittorrent metainfo file, as specified in BEP-0003

    :param pkg_root_dir: the directory containing the packages
    :param pkg_num: the number of the package whose bundle list will be returned
    :param tree_size: the tree_size up to which the bundles must be considered
    :return: A list of dicts to fit in the files property of a bittorrent metainfo file
    """

    # Get the bundle list
    pkg_dir = os.path.join(pkg_root_dir, build_package_name(pkg_num))
    bundle_list = get_bundle_list(pkg_dir, tree_size)

    file_list = []
    for bundle in bundle_list:
        # The dict must contain the path relative to the bittorrent download dir + the name the user choose to store
        # the files downloaded from this torrent. As such, the file_path is just the relative path to the bundle, from
        # the pkg_root_dir
        # The dict must also contain the length of said file
        file_info = os.stat(os.path.join(pkg_dir, bundle))
        file_path = [build_package_name(pkg_num), bundle]
        file_list.append(
            {
                'length': file_info.st_size,
                'path': file_path
            }
        )

    # The torrent also contains the STH file for a specified tree_size
    sth_fn = build_sth_name(tree_size)
    file_info = os.stat(os.path.join(pkg_root_dir, sth_fn))
    file_list.append({'length': file_info.st_size, 'path': [sth_fn]})

    # The info file containing the pkg_hash and the merkle proof for this package up to the STH must be included for
    # downloaders to be able to verify this package
    info_file_fn = build_info_file_name(pkg_num, tree_size)
    file_info = os.stat(os.path.join(pkg_root_dir, info_file_fn))
    file_list.append({'length': file_info.st_size, 'path': [info_file_fn]})

    return file_list


def get_pieces(pkg_root_dir, files, piece_length):
    """ get_pieces generates all the SHA-1 digests for every piece of the torrent. For this, it opens, in order, all
    the files that must be included in the torrent and hashes them. If a file size is not a multiple of the piece_length
    then the end of one file is concatenated to the beginning of the next file. Only the last file is hashed as an
    incomplete piece.

    :param pkg_root_dir: the directory containing the packages
    :param files: the list of dicts generated by the get_file_list function
    :param piece_length: the size of each piece of this torrent
    :return: yields hashes of pieces
    """
    s = b''
    for f in files:
        file_path = os.path.join(pkg_root_dir, os.sep.join(f['path']))
        with open(file_path, 'rb') as fd:
            buf = fd.read(piece_length)
            while len(buf) != 0:
                s += buf
                if len(s) >= piece_length:
                    h = hashlib.sha1()
                    h.update(s[:piece_length])
                    yield h.digest()
                    s = s[piece_length:]
                buf = fd.read(piece_length)
    h = hashlib.sha1()
    h.update(s[:piece_length])
    yield h.digest()


def write_torrent_file(torrent_dir, url, pkg_num, tree_size, torrent):
    """ write_torrent_file writes into the torrent_dir the provided torrent dict.

    :param torrent_dir: the directory to which the torrent must be written
    :param url: the url of the log whose bundles are part of this torrent (used to name the torrent file)
    :param pkg_num: the package number whose bundles are part of this torrent (also used to name the torrent file)
    :param tree_size: the tree_size of the STH included in the torrent file (also used to name the torrent file)
    :param torrent: the torrent dict; this function is bencoding this object before it is written on disk
    :return: None
    """
    bencoded_torrent = bencode(torrent)

    filename = build_torrent_name(url, pkg_num, tree_size)
    filepath = os.path.join(torrent_dir, filename)

    with open(filepath, 'wb') as fd:
        fd.write(bencoded_torrent)


def write_magnet_link(torrent_dir, url, pkg_num, tree_size, btih, dn, trackers, peers):
    """ write_magnet_link builds a magnet link from the provided informations and write it down on disk

    :param torrent_dir: the directory that will contain the magnet link file
    :param url: the url of the log whose bundles may be downloaded from this magnet (used to name the magnet file)
    :param pkg_num: the package number whose bundles may be downloaded from this magnet (used to name the magnet file)
    :param tree_size: the tree_size of the STH that can be downloaded from this magnet (used to name the magnet file)
    :param btih: the Bittorrent Info Hash, that will be part of the magnet link
    :param dn: the name of the torrent (as it will appear in the BT client I suppose)
    :param trackers: the list of trackers for this torrent
    :param peers: the list of peers for this torrent
    :return: None
    """
    filename = build_magnet_name(url, pkg_num, tree_size)
    filepath = os.path.join(torrent_dir, filename)

    magnet_url = b'magnet:?xt=urn:btih:' + codecs.getencoder('hex')(btih)[0] + b'&dn=' + bytes(dn, 'UTF-8')
    if not isinstance(peers, type(None)):
        for peer in peers:
            magnet_url += b'&x.pe=' + bytes(peer, 'UTF-8')
    if not isinstance(trackers, type(None)):
        for tracker in trackers:
            magnet_url += b'&tr=' + bytes(tracker, 'UTF-8')

    with open(filepath, 'wb') as fd:
        fd.write(magnet_url)


def create_torrent(args):
    """ create_torrent creates a torrent and the magnet link for a specified package

    :param args: a tuple containing :
      - torrent_dir: the directory in which the metainfo file and the magnet link will be stored
      - pkg_root_dir: the directory containing the packages for the log at url
      - url: the url of the log for which a torrent is generated
      - pkg_num: the package number of the package that will be put in the torrent
      - tree_size: the tree_size up to which the bundles will be considered (must be a tree_size of STH)
      - trackers_lst: a list of trackers URL
      - peers: a list of peers, each one in the format specified in BEP-0009
      - suggested_name: the log name, as it will appear in the metainfo name attribute
      - param asn: the number of the AS from which the CT log archived were fetched
    :return: the torrent dict
    """
    (torrent_dir, pkg_root_dir, url, pkg_num, tree_size, trackers_lst, peers_lst, suggested_name, asn) = args

    print('Creating torrent for package {}'.format(pkg_num))

    # Get the list of dict for the files property
    files = get_file_list(pkg_root_dir, pkg_num, tree_size)

    # Compute the size of the pieces. For this we try to find a value that generates roughtly 1500 pieces. This
    # threshold was chosen almost randomly (i.e. by reading various threads on various sites about the ideal piece count
    # in a torrent.
    total_size = sum([f['length'] for f in files])
    # piece length is either 32KB or it is computed so that we roughly have 1500 pieces and that the piece length is a
    # multiple of 16KB
    piece_length = max(1 << 15, ((total_size//1500) >> 13) << 13)

    # Build the piece property by concatenating all pieces in binary format
    pieces = b''.join(list(get_pieces(pkg_root_dir, files, piece_length)))

    # Build the info section so that it can be encoded only once and then hashed
    info_section = {
            'name': suggested_name,
            'piece length': piece_length,
            'pieces': pieces,
            'files': files
    }

    # Hash the info_section to generate the BTIH
    bencoded_info_section = bencode(info_section)
    h = hashlib.sha1()
    h.update(bencoded_info_section)
    btih = h.digest()

    # Build the torrent
    torrent = {
        'info': Raw(bencoded_info_section),
        'creation date': int(time.time()),
        'comment': 'Downloaded from AS{}'.format(asn),
        'created by': 'ATBTCT (https://github.com/X-Cli/ATBTCT)',
    }

    if len(trackers_lst) > 0:
        torrent['announce'] = trackers_lst[0]
        torrent['announce-list'] = [trackers_lst]
    elif len(peers_lst) > 0:
        # Tracker-less Torrent; let's try and use the nodes metadata then
        torrent['peers'] = [peer.split(':') for peer in peers_lst]

    # Write the various files (metainfo file and magnet link) on disk
    write_magnet_link(torrent_dir, url, pkg_num, tree_size, btih, info_section['name'], trackers_lst, peers_lst)

    write_torrent_file(torrent_dir, url, pkg_num, tree_size, torrent)

    return torrent, btih, pkg_num, total_size


def merge_magnets(torrent_dir, suggested_name):
    """ merge_magnets reads all magnet files that pertain to a specific log archive, builds a list of them and write
    that list into a file, so that people can download it and iter on it easily

    :param torrent_dir: the directory containing the magnets
    :param suggested_name: the name to use to build the magnet links file name
    :return: None
    """

    magnet_list = []

    # For each magnet file pertaining to the log of interest, append the magnet link to the list
    for magnet_file in [
        fn
        for fn in os.listdir(torrent_dir)
        if fn.startswith(suggested_name) and fn.endswith('.magnet')
    ]:
        file_path = os.path.join(torrent_dir, magnet_file)
        with open(file_path, 'rb') as fd:
            magnet_link = fd.read()
        magnet_list.append(magnet_link)

    # Write the list in a single file
    file_path = os.path.join(torrent_dir, '{}.magnets'.format(suggested_name))
    with open(file_path, 'wb') as fd:
        fd.write(b'\n'.join(magnet_list))


def check_rss_dom_structure(doc):
    """ check_rss_dom_structure checks that the provided DOM document is correctly formatted and extracts the DOM
    Element of the channel tag of this RSS feed

    :param doc: the RSS to check as a DOM Document
    :return: The DOM element of the channel tag
    """
    if isinstance(doc, type(None)) or not doc.hasChildNodes() or len(doc.childNodes) != 1:
        raise Exception('Invalid document')
    root_elmt = doc.childNodes[0]
    if (
        root_elmt.nodeName != 'rss'
        or not root_elmt.hasChildNodes()
        or len(root_elmt.childNodes) != 1
        or root_elmt.getAttribute('version') != '2.0'
    ):
        raise Exception('Invalid root element')
    channel_elmt = root_elmt.childNodes[0]
    has_title = False
    has_description = False
    has_link = False
    for elmt in channel_elmt.childNodes:
        if elmt.nodeName == 'title':
            has_title = True
        elif elmt.nodeName == 'description':
            has_description = True
        elif elmt.nodeName == 'link':
            has_link = True
    if not has_title or not has_description or not has_link:
        raise Exception('Missing header element')

    return channel_elmt


def init_rss_dom_structure(url):
    """ init_rss_dom_structure initializes a RSS feed for a log

    :param url: URL of the log whose archives can be downloaded with this RSS feed
    :return: the DOM document and the channel DOM Element of the Channel tag
    """
    doc = xml.dom.minidom.Document()
    root_elmt = doc.createElement('rss')
    root_elmt.setAttribute('version', '2.0')
    doc.appendChild(root_elmt)

    channel_elmt = doc.createElement('channel')
    root_elmt.appendChild(channel_elmt)

    ttl_elmt = doc.createElement('ttl')
    ttl_txt = doc.createTextNode(str(24*60))  # One day TTL (24 * 60 minutes)
    ttl_elmt.appendChild(ttl_txt)
    channel_elmt.appendChild(ttl_elmt)

    title_elmt = doc.createElement('title')
    title_txt = doc.createTextNode('ATBTCT RSS feed for the CT log at {}'.format(url))
    title_elmt.appendChild(title_txt)
    channel_elmt.appendChild(title_elmt)

    desc_elmt = doc.createElement('description')
    desc_txt = doc.createTextNode(
        'References the list of torrents that one can add to its BitTorrent client in order to get an archive of the CT log at {}.'.format(url)
    )
    desc_elmt.appendChild(desc_txt)
    channel_elmt.appendChild(desc_elmt)

    link_elmt = doc.createElement('link')
    link_txt = doc.createTextNode('https://github.com/X-Cli/ATBTCT')
    link_elmt.appendChild(link_txt)
    channel_elmt.appendChild(link_elmt)

    return doc, channel_elmt


def update_rss_feed(torrent_dir, suggested_name, url, download_url, tree_size, torrents):
    """ update_rss_feed create a RSS feed referencing torrents provided as parameter or update an existing RSS feed
    with them

    :param torrent_dir: Directory where is/will be stored the RSS feed
    :param suggested_name: the name that will be used to create the RSS name
    :param url: The URL of the log the torrents were downloaded
    :param download_url: The HTTP URL prefix where the torrent files can be found
    :param tree_size: The tree_size at the moment were the torrents were created
    :param torrents: a list of tuples; these tuples contain:
      - the torrent as a dict
      - the Bittorrent Info Hash of this torrent
      - the number of the package that is stored in this torrent
      - the total length of the files that are stored in this torrent
    :return: None
    """
    # Fetching the existing feed, if possible
    filepath = os.path.join(torrent_dir, '{}.rss'.format(suggested_name))
    try:
        with open(filepath, 'rb') as fd:
            doc = xml.dom.minidom.parse(fd)

    except IOError:
        # The RSS file does not exist; it is probably a first run
        doc = None

    # Fixing download URL, if need be, such that it ends with a slash
    if download_url[-1] != '/':
        download_url += '/'

    # Building/Verifying the XML structure
    try:
        chan = check_rss_dom_structure(doc)
    except Exception:
        doc, chan = init_rss_dom_structure(url)

    for torrent_data in torrents:
        item = doc.createElement('item')
        chan.appendChild(item)

        title_elmt = doc.createElement('title')
        title_txt = doc.createTextNode('Package {} for tree_size {}'.format(torrent_data[2], tree_size))
        title_elmt.appendChild(title_txt)
        item.appendChild(title_elmt)

        desc_elmt = doc.createElement('description')
        desc_txt = doc.createTextNode(
            'Comment: {} Creation Date: {}'.format(torrent_data[0]['comment'], torrent_data[0]['creation date'])
        )
        desc_elmt.appendChild(desc_txt)
        item.appendChild(desc_elmt)

        guid_elmt = doc.createElement('guid')
        fp = codecs.getencoder('hex')(torrent_data[1])[0]
        guid_txt = doc.createTextNode(fp.decode('UTF-8'))
        guid_elmt.appendChild(guid_txt)
        item.appendChild(guid_elmt)

        enclosure_elmt = doc.createElement('enclosure')
        enclosure_elmt.setAttribute('url', download_url + build_torrent_name(url, torrent_data[2], tree_size))
        enclosure_elmt.setAttribute('type', 'application/x-bittorrent')
        enclosure_elmt.setAttribute('len', str(torrent_data[3]))
        item.appendChild(enclosure_elmt)

    with open(filepath, 'wb') as fd:
        fd.write(doc.toxml('UTF-8'))


def create_torrents(torrent_dir, pkg_root_dir, url, download_url, start_package, last_package, tree_size, trackers,
                    peers, suggested_name, asn, workers_cnt=None):
    """ create_torrents call create_torrent for each package. Packages can be handled simultaneously by multiple
    concurrent processes.

    :param torrent_dir: the directory into which metainfo files and magnet links will be stored
    :param pkg_root_dir: the directory containing the log archives
    :param url: the url of the log whose torrents must be created
    :param download_url: HTTP URL from which the torrent files can be downloaded
    :param start_package: the first package for which a torrent must be generated
    :param last_package: the last package for which a torrent must be generated
    :param tree_size: the tree_size, used to determine the STH to include in the torrent and name various things
    :param trackers: a list of trackers to put into the torrent file
    :param peers: a list of peers, in the format specified by BEP-0009
    :param suggested_name: the name of the log, as it will appear in the torrent metainfo file
    :param asn: the number of the AS from which the CT log archived were fetched
    :param workers_cnt: the number of concurrent processes that will work on making these torrents
    :return: None
    """

    p = multiprocessing.Pool(workers_cnt)
    params = [
        (torrent_dir, pkg_root_dir, url, pkg_num, tree_size, trackers, peers, suggested_name, asn)
        for pkg_num in range(start_package, last_package+1)
    ]
    torrents = p.map(create_torrent, params)
    p.terminate()
    p.join()

    merge_magnets(torrent_dir, suggested_name)
    update_rss_feed(torrent_dir, suggested_name, url, download_url, tree_size, torrents)
