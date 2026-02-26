#!/usr/bin/python3

import os
import sys
import time
import shutil
import stat
import logging
import hashlib
import argparse
import os

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


SIGNATURE_DIR = "/var/lib/antivirus"
LOG_FILE = "/var/log/antivirus.log"
QUARANTINE_DIR = "quarantine"

def initial_scan(scan_path, signatures):
    logging.info("Starting initial full system scan...")

    for root, dirs, files in os.walk(scan_path):
        for file in files:
            full_path = os.path.join(root, file)
            try:
                scan_file(full_path, signatures)
            except Exception:
                logging.exception(f"Error scanning {full_path}")

    logging.info("Initial scan complete.")

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

def ensure_environment():
    os.makedirs(SIGNATURE_DIR, exist_ok=True)
    os.makedirs(QUARANTINE_DIR, exist_ok=True)

    for name in ["signatures_sha256.txt"]:
        target = os.path.join(SIGNATURE_DIR, name)
        if not os.path.exists(target):
            if os.path.exists(name):
                shutil.copy(name, target)
                logging.info(f"Copied default signature file {name}")
            else:
                logging.error(f"Missing default signature file: {name}")
                sys.exit(1)

def load_signatures():
    sig_file = os.path.join(SIGNATURE_DIR, "signatures_sha256.txt")
    with open(sig_file, "r") as f:
        return set(line.strip() for line in f if line.strip())

def compute_sha256(path):
    try:
        sha = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha.update(chunk)
        return sha.hexdigest()
    except:
        return None


def scan_file(path, signatures):
    if not os.path.isfile(path):
        return

    file_hash = compute_sha256(path)
    if not file_hash:
        return

    #logging.info(f"Scanned: {path}")

    if file_hash in signatures:
        logging.warning(f"Malicious file detected: {path}")

        mode = os.stat(path).st_mode
        os.chmod(path,
                 mode & ~stat.S_IXUSR &
                 ~stat.S_IXGRP &
                 ~stat.S_IXOTH)

        dest = os.path.join("/var/lib/antivirus/quarantine",
                            os.path.basename(path))

        os.makedirs("/var/lib/antivirus/quarantine", exist_ok=True)

        shutil.move(path, dest)

        logging.warning(f"File quarantined: {dest}")


class AVHandler(FileSystemEventHandler):
    def __init__(self, signatures):
        self.signatures = signatures

    def on_created(self, event):
        if not event.is_directory:
            scan_file(event.src_path, self.signatures)

    def on_modified(self, event):
        if not event.is_directory:
            scan_file(event.src_path, self.signatures)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("watch_path", help="Folder to monitor")
    args = parser.parse_args()

    if not os.path.isdir(args.watch_path):
        print("Invalid directory.")
        sys.exit(1)

    ensure_environment()
    signatures = load_signatures()

    logging.info("Antivirus service started.")
    
    initial_scan(args.watch_path, signatures)

    observer = Observer()
    observer.schedule(
        AVHandler(signatures),
        path=args.watch_path,
        recursive=True
    )
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()

main()
