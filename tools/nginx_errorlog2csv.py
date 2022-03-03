# Parses all Nginx error logs in the folder to CSV file
# Author: Gökay Atar
import glob
import re
import csv
import argparse


def get_files(folder=None):
    path = folder + "/error.log*"
    files = glob.glob(path)
    if len(files) == 0:
        print("error.log file not found")
        exit(1)
    return files


def log_parser(file):
    pattern = """^(?P<timestamp>\d{4}/\d{2}/\d{2}\ \d{2}:\d{2}:\d{2})
        \ \[(?P<severity>emerg|alert|crit|error|warn|notice|info)\]
        \ (?P<process_id>\d+)
        \#(?P<thread_id>\d+):
        \ \*(?P<connection_id>\d+)
        \ (?P<error>.+?)
        (?:\ while\ (?P<context>.+?))?
        ,\ client:\ (?P<client_ip>\d+\.\d+\.\d+\.\d+)
        ,\ server:\ (?P<server>.+?)
        (?:,\ request:\ \"(?P<request_method>[A-Z]+?)
            \ (?P<request_path>\/.+?)
            \ (?P<request_protocol>.+?)\")?
        (?:,\ upstream:\ \"(?P<upstream>.+?)\")?
        (?:,\ host:\ \"(?P<host>.+?)\")?
        (?:,\ referrer:\ \"(?P<referrer>.+?)\")?
        $"""

    compiled_pattern = re.compile(pattern, re.VERBOSE)
    for match in compiled_pattern.finditer(file):
        catch = match.groupdict()
        return catch


def write_to_csv(row):
    with open(folder + "/error.csv", "a") as csvfile:
        fieldnames = [
            "timestamp",
            "severity",
            "process_id",
            "thread_id",
            "connection_id",
            "error",
            "context",
            "client_ip",
            "server",
            "request_method",
            "request_path",
            "request_protocol",
            "upstream",
            "host",
            "referrer",
        ]

        try:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            if csvfile.tell() == 0:
                writer.writeheader()
            writer.writerow(row)
        except Exception as e:
            pass


def main(folder):
    for file in get_files(folder):
        with open(file) as f:
            for num, line in enumerate(f):
                print(num, "--", f.name, "-", log_parser(line))
                write_to_csv(log_parser(line))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Parses all Nginx error logs in the folder to CSV file"
    )
    parser.add_argument(
        "-f",
        "--folder",
        help="Path to folder with error.log files. Default: current folder",
        default=".",
        type=str,
    )
    args = parser.parse_args()
    folder = args.folder
    main(folder)
