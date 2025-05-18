# PassParser

This is yet again a script I wrote for myself.
PassParser is a tool that reads the /etc/passwd file on Unix machines and processes them.
It can either print out system accounts or turn them into a userlist or a json file.

By default the tool prints the information found in the passwd file in a readable format. This includes every column (e.g. UID, Hash location, etc.).

I also added a filter flag to only show user/service accounts based on likeliness.

This means each account has a "user likeliness" which is determined by the data related to each account, such as:
- UID and GID
- Home directory
- Shell

This tool is WIP, meaning it could contain bugs and is far from being finished.
I have plans for adding a likeliness treshold, fix the whole scale in general, since it can go into negatives, etc.

## Requirements
- Python 3

## Syntax

The tool follows a basic syntax

```bash
./passparser.py (-f | --filter) [user | service] (-o | --output) [list | json] [filename]
```

Example - Creating a userlist for pentesting:
```bash
./passparser.py -f user -o list userlist.txt
```

Example - Creating a JSON file of existing service accounts:
```bash
./passparser.py -f service -o json services.json
```

The order of the filter and output flags don't matter.
