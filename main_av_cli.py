#!/usr/bin/python3

import ctypes
import rich
import argparse
import sys
import os
import shutil
import stat
import time

# load shared library
lib = ctypes.CDLL("./modules.so")

# a bunch of C argument signature stuff
lib.compute_md5_hash.argtypes = [
    ctypes.POINTER(ctypes.c_char_p),
    ctypes.c_int
]
lib.compute_md5_hash.restype = ctypes.c_int

class MD5Result(ctypes.Structure):
    _fields_ = [
        ("hashes", ctypes.POINTER(ctypes.c_char_p)),
        ("paths", ctypes.POINTER(ctypes.c_char_p)),
        ("count", ctypes.c_int),
    ]

lib.compute_md5_hash.restype = MD5Result

lib.free_md5_result.argtypes = [MD5Result]

class SHA256Result(ctypes.Structure):
    _fields_ = [
        ("hashes", ctypes.POINTER(ctypes.c_char_p)),
        ("paths", ctypes.POINTER(ctypes.c_char_p)),
        ("count", ctypes.c_int),
    ]

lib.compute_sha256_hash.argtypes = [
    ctypes.POINTER(ctypes.c_char_p),
    ctypes.c_int
]
lib.compute_sha256_hash.restype = SHA256Result

lib.free_sha256_result.argtypes = [SHA256Result]



lib.list_files_recursive.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_int)
]

lib.list_files_recursive.restype = ctypes.POINTER(ctypes.c_char_p)

lib.free_file_list.argtypes = [
    ctypes.POINTER(ctypes.c_char_p),
    ctypes.c_int
]


class DetectionResult(ctypes.Structure):
    _fields_ = [
        ("hits", ctypes.POINTER(ctypes.c_char_p)),
        ("count", ctypes.c_int),
    ]

lib.detect_malicious.argtypes = [
    ctypes.POINTER(ctypes.c_char_p),
    ctypes.POINTER(ctypes.c_char_p),
    ctypes.c_int,
    ctypes.c_char_p,
]

lib.detect_malicious.restype = DetectionResult
lib.free_detection_result.argtypes = [DetectionResult]


# main program begin
parser = argparse.ArgumentParser()

parser.add_argument('target_folder', help="Path of folder to scan")
parser.add_argument('malicious_hash_file', nargs='?', default='signatures_sha256.txt', help="Path of file with known malicious hashes.")
parser.add_argument('-hash', '--hash_function', default='sha-256', help="Hash function to hash files with (md5 or sha-256)")
parser.add_argument('-v', '--verbose',
                    action='store_true', help="Show verbose output")

args = parser.parse_args()

folder = args.target_folder
malicious_hash_file = args.malicious_hash_file
hash_function = args.hash_function
verbose = args.verbose

#print(folder, verbose, hash_function)

rich.print("[purple bold]AntiVirus Scanner by sviatko124[/purple bold]\n")

if not os.path.exists(malicious_hash_file):
    rich.print(f"[red bold]Error:[/red bold] Signature file '{malicious_hash_file}' does not exist.")
    sys.exit(1)

if not os.path.isfile(malicious_hash_file):
    rich.print(f"[red bold]Error:[/red bold] '{malicious_hash_file}' is not a valid file.")
    sys.exit(1)

if hash_function != "md5" and hash_function != "sha-256":
    rich.print("[red bold]Error: [/red bold]Please supply existing hash function or leave blank for default.")
    sys.exit(1)

count = ctypes.c_int()

start_time = time.time()

files = lib.list_files_recursive(str.encode(folder), ctypes.byref(count))

total_files_scanned = count.value
total_threats = 0

if verbose:
    rich.print("[purple]All file paths to be scanned:[/purple]")
    for i in range(count.value):
        print(files[i].decode())


# call hash function with new list of paths

if hash_function == "md5":
    result = lib.compute_md5_hash(files, count.value)
elif hash_function == "sha-256":
    result = lib.compute_sha256_hash(files, count.value)

filehashes = []
filepaths = []

for i in range(result.count):
    filehashes.append(result.hashes[i].decode())
    filepaths.append(result.paths[i].decode())

if verbose:
    rich.print("[purple]Every file hash:[/purple]")
    for h, p in zip(filehashes, filepaths):
        print(h, p)

# detect files
db_path = malicious_hash_file.encode()

det = lib.detect_malicious(
    result.hashes,
    result.paths,
    result.count,
    db_path
)

total_threats = det.count

if det.count == 0:
    rich.print("[green bold]No threats detected.[/green bold]")
else:
    path_to_hash = dict(zip(filepaths, filehashes))
    rich.print("[red bold]Detected threats:[/red bold]")

    quarantine_dir = "quarantine"
    os.makedirs(quarantine_dir, exist_ok=True)

    for i in range(det.count):
        path = det.hits[i].decode()
        hash_val = path_to_hash.get(path, "UNKNOWN")

        rich.print("[bold]Malicious file path:[/bold]", path)
        rich.print("[bold]Malicious file hash:[/bold]", hash_val)

        try:
            filename = os.path.basename(path)
            quarantine_path = os.path.join(quarantine_dir, filename)

            shutil.move(path, quarantine_path)

            current_mode = os.stat(quarantine_path).st_mode
            os.chmod(quarantine_path,
                     current_mode & ~stat.S_IXUSR &
                     ~stat.S_IXGRP &
                     ~stat.S_IXOTH)

            rich.print("[yellow]Moved file to quarantine.[/yellow]\n")

        except Exception as e:
            rich.print(f"[red]Failed to quarantine: {e}[/red]\n")

end_time = time.time()
scan_duration = end_time - start_time

rich.print("\n[bold blue]Scan Summary[/bold blue]")
rich.print("[bold]Files scanned:[/bold]", total_files_scanned)
rich.print("[bold]Threats detected:[/bold]", total_threats)
rich.print("[bold]Scan duration:[/bold]", f"{scan_duration:.5f} seconds")



# free all memory

if hash_function == "md5":
    lib.free_md5_result(result)
elif hash_function == "sha-256":
    lib.free_sha256_result(result)

lib.free_file_list(files, count.value)

lib.free_detection_result(det)

