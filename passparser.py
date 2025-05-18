#!/usr/bin/env python3

import sys
import json


class User:
    def __init__(self, fields):
        self.username = fields[0]
        self.hash_marker = fields[1]
        self.uid = int(fields[2])
        self.gid = int(fields[3])
        self.full_name = fields[4]
        self.home_dir = fields[5]
        self.shell_dir = fields[6]
        self.likeliness = self.calculate_user_likeliness()

    def calculate_user_likeliness(self):
        likeliness = 0
        if self.uid >= 1000:
            likeliness += 1
        if self.gid >= 1000:
            likeliness += 1
        if self.home_dir.startswith("/home/"):
            likeliness += 2
        if self.shell_dir in [
            "/bin/bash",
            "/bin/sh",
            "/bin/zsh",
            "/usr/bin/bash",
            "/usr/bin/sh",
            "/usr/bin/zsh",
        ]:
            likeliness += 2
        elif "nologic" in self.shell_dir or "false" in self.shell_dir:
            likeliness -= 2

        return likeliness


def open_file():
    try:
        userfile = open("/etc/passwd", "r")

    except Exception:
        sys.exit("Insufficient privileges.")

    return userfile


def print_user_info(user):
    def print_kv(key, value):
        print(f"{key:<22}\t\t{value}")

    print("---")
    print_kv("Username:", user.username)
    print_kv("UID:", user.uid)
    print_kv("GID:", user.gid)
    print_kv("Full Account Name:", user.full_name)
    print_kv("Home:", user.home_dir)
    print_kv("Shell:", user.shell_dir)
    print_kv("User Likeliness:", user.likeliness)

    if user.hash_marker == "x":
        print_kv("Password Hash:", "Stored in /etc/shadow")
    elif user.hash_marker == "":
        print_kv("Password Hash:", "USER HAS NO PASSWORD!!")
    else:
        print_kv("Password Hash:", user.hash_marker)

    if user.likeliness >= 4:
        print("\nThis account is very likely to be a real user's.")
    elif user.likeliness >= 2:
        print("\nThis account might be a real user's.")
    else:
        print("\nThis account is likely a service account.")


def filter_func(argv, filter_index):
    if filter_index == len(argv) - 1:
        sys.exit("Please provide a filter.")
    filter_type = argv[filter_index + 1]
    if filter_type == "user" or filter_type == "service":
        FILTER = filter_type
    elif filter_type is None:
        sys.exit("Please provide a filter.")
    else:
        sys.exit(f"The filter {filter_type} is not known.")
    return FILTER or None


def handle_output(argv, output_index):
    output_options = ["list", "json"]
    if output_index == len(argv) - 2:
        sys.exit("Please provide an output option and name")
    output_type = argv[output_index + 1]
    if output_type not in output_options:
        sys.exit(f"Please choose a valid output format: {', '.join(output_options)}")
    return argv[output_index + 1], argv[output_index + 2]


def main():
    FILTER = None
    OUTPUT_REQUESTED = False
    userfile = open_file()
    output_option = None
    filename = None
    output_index = None

    if len(sys.argv) >= 2:
        filter_index = None
        if "-f" in sys.argv:
            filter_index = sys.argv.index("-f")
        if "--filter" in sys.argv:
            filter_index = sys.argv.index("--filter")

        if filter_index:
            FILTER = filter_func(sys.argv, filter_index)

        if "-o" in sys.argv or "--output" in sys.argv:
            output_index = (
                sys.argv.index("-o") if "-o" in sys.argv else sys.argv.index("--output")
            )

        output_option, filename = None, None
        if output_index:
            output_option, filename = handle_output(sys.argv, output_index)

        if output_option and filename:
            try:
                output_file = open(filename, "x")
            except FileExistsError:
                output_file = open(filename, "a")

    for line in userfile:
        fields = line.strip().split(":")

        if len(fields) < 7:
            continue

        user = User(fields)
        user_likeliness = user.likeliness

        if (
            (FILTER == "user" and user_likeliness >= 3)
            or (FILTER == "service" and user_likeliness <= 3)
            or FILTER is None
        ):
            if (output_option and OUTPUT_REQUESTED is True) or not output_option:
                print_user_info(user)
            if output_option == "list":
                output_file.write(f"{user.username}\n")
            elif output_option == "json":
                user_dict = {
                    "username": user.username,
                    "uid": user.uid,
                    "gid": user.gid,
                    "full_name": user.full_name,
                    "home_dir": user.home_dir,
                    "shell_dir": user.shell_dir,
                    "hash_marker": user.hash_marker,
                    "user_likeliness": user.likeliness,
                }
                json_object = json.dumps(user_dict, indent=4)
                output_file.write(f"{json_object}\n")


if __name__ == "__main__":
    main()
