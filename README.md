# ATBTCT: AuTomated BitTorrent mirrors of Certificate Transparency

This toolchain allows you to download the certificates from a Certificate
Transparency log that is listed as a
[known log](https://certificate-transparency.org/known-logs).

The downloaded certificate entries are verified cryptographically using the
public keys found in the
[log_list.json](https://www.certificate-transparency.org/known-logs/log_list.json)
file and by rebuilding the Merkle Tree from the downloaded entries.

Finally, this toolchain can create Bittorrent metainfo files (also known as
.torrent files) a RSS feed of these torrents and magnet links for you 
to seed the downloaded data.

## List of initiatives using this toolchain (non-exhaustive)

* https://www.x-cli.eu/ct

## Requirements

This toolchain is written in Python3. It should, at least, work with Python 3.4 and 3.5.

The only dependency that is not part of Python standard library is
[cryptography](https://cryptography.io). You will need a "recent" version of
this library; one that supports ECDSA. The version that is installed by pip, at
the time of writing, works just fine.

You can install the dependencies by running:
```
pip install -r requirements.txt
```

## Running the toolchain

The simplest way to run this toolchain is by having the atbtct directory 
into your PYTHONPATH and run the module.

```
python3 -m "atbtct" --help
```

Re-running the toolchain with the same parameters and config file will update
the log archive and create the new torrents accordingly.

You can run the toolchain with the following options to give it a try. 
You will want to have tens of GB of free storage, before running this 
command.

```
$ mkdir /tmp/{torrents,log_archive}

$ wget -o /tmp/log_list.json "https://www.certificate-transparency.org/known-logs/log_list.json"

$ cat > /tmp/config.ini << EOF 
[General]
# Log list from https://www.certificate-transparency.org/known-logs/log_list.json
log_list_file=/tmp/log_list.json

# URL prefixing the torrent files (https://example.com/torrents/some_log_file.torrent)
download_url=https://example.com/torrents/

# Directory containing data
root_dir=/tmp/log_archive
torrent_dir=/tmp/torrents

# Number of the AS from which the log were fetched
ASN=64496

# Number of concurrent threads
workers=2

[Trackers]
tracker1=http://example.com:8000/announce
tracker2=http://example.net:6969/announce

[Peers]
peer1=example.com:51413
peer2=example.net:51413
EOF

$ python3 -m "atbtct" -c /tmp/config.ini -u ct.googleapis.com/rocketeer 
```

The previous command will download the Google Rocketeer log archive and 
will put the log archive in `/tmp/log_archive`. The torrents and magnet
links will be stored in `/tmp/torrents`.

You may have seen that the ATBTCT module may be invoked with expert mode options.
These modes allow you to run parts of the toolchain, for instance to regenerate 
some metainfo files that were corrupted or lost, by mistake. These modes
should not be used until you have read the source code and you understand what
you are doing with them.
