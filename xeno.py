#!/usr/bin/env python3

import os
import bsddb3 as db  # For Berkeley DB compatibility
from email.utils import parseaddr
from email.header import decode_header
from email_validator import validate_email, EmailNotValidError
import argparse
import sys

# GLOBAL
debugging = False
dbfile = ""

def decode_email_header(header_value):
    """Decode email headers that may be encoded in formats like '=?UTF-8?B?...?='."""
    decoded_parts = decode_header(header_value)
    header = ''
    for part, encoding in decoded_parts:
        if isinstance(part, bytes):
            header += part.decode(encoding or 'utf-8')
        else:
            header += part
    return header

def main():
    """Main function to handle argument parsing and execution."""
    global debugging, dbfile

    parser = argparse.ArgumentParser(
        description=('Check e-mail addresses in input (UNIX mailbox format) '
                     'against a known list of addresses.')
    )
    parser.add_argument('-a', '--add', help='Add address entry')
    parser.add_argument('-r', '--remove', help='Remove address entry')
    parser.add_argument('-c', '--check', action='store_true',
                        help='Check if From: address is in DB')
    parser.add_argument('-l', '--list', action='store_true',
                        help='List contents of database')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='Enable debug mode')
    parser.add_argument('-f', '--file', help=('Use alternate DB file, '
                        'default is $HOME/.xeno.db'))
    parser.add_argument('-s', '--strict', action='store_true',
                        help='Require addresses to have an "@"')

    args = parser.parse_args()
    debugging = args.debug

    dbfile = args.file if args.file else os.path.join(os.getenv('HOME'),
                                                      '.xeno.db')

    if debugging:
        print(f"DB file = {dbfile}\n")

    # Load or create the database
    unique = open_db()

    if args.list:
        list_addresses(unique)
    elif args.add:
        db_access('update', unique, args.add, args.strict)
    elif args.remove:
        db_access('delete', unique, args.remove)
    else:
        # Default behavior: read from stdin, extract addresses, and update DB
        process_input(unique, args)

    close_db(unique)

def open_db():
    """Open the database file, creating it if necessary."""
    try:
        db_handle = db.hashopen(dbfile, 'c')
        return db_handle
    except db.db.DBError as e:
        print(f"Cannot open file {dbfile}: {e}", file=sys.stderr)
        sys.exit(1)

def close_db(db_handle):
    """Close the database connection."""
    db_handle.close()

def list_addresses(db_handle):
    """List all addresses in the database."""
    for key in db_handle.keys():
        print(key.decode('utf-8'))
    sys.exit(0)

def db_access(action, db_handle, key, strict=False):
    """Perform CRUD operations on the database.

    Args:
        action: One of 'update', 'query', 'delete'.
        db_handle: The database object.
        key: The e-mail address key.
        strict: If True, requires e-mails to pass validation.
    """
    key = key.lower()

    if strict:
        try:
            validate_email(key)
        except EmailNotValidError as e:
            if debugging:
                print(f"Invalid email: {e}")
            return

    if action == 'update':
        if strict and '@' not in key:
            if debugging:
                print(f"Bad address (no @)... skipping\n")
            return

        if db_access('query', db_handle, key):
            if debugging:
                print(f"No update:\n  {key} is already in DB\n")
        else:
            db_handle[key.encode('utf-8')] = b'1'
            if debugging:
                print(f"Updating database:\n  adding {key} to DB\n")
    elif action == 'query':
        return key.encode('utf-8') in db_handle
    elif action == 'delete':
        if key.encode('utf-8') in db_handle:
            del db_handle[key.encode('utf-8')]
            if debugging:
                print(f"Removing {key} from DB\n")

def process_input(db_handle, args):
    """Read and process headers from stdin in Unix mailbox format.

    Args:
        db_handle: The database object.
        args: Command-line arguments.
    """
    which_hdrs = ['From', 'To', 'Cc']  # Common headers that hold email addresses

    in_hdr = False
    headers = []
    
    # Read and process input line by line
    for line in sys.stdin:
        line = line.rstrip()
        
        if debugging:
            print(f"Processing line: {line}")  # Debug each line
        
        # Detect beginning of the email header section (e.g., From line)
        if not in_hdr and line.startswith('From '):
            in_hdr = True
            headers = []

        if in_hdr:
            if line == '':  # Empty line indicates the end of headers
                in_hdr = False
                process_header("\n".join(headers), which_hdrs, db_handle, args)
            else:
                if line.startswith(" "):  # Continuation of previous line
                    headers[-1] += line.strip()
                else:
                    headers.append(line)

def process_header(header_block, which_hdrs, db_handle, args):
    """Extract and process email addresses from a header block.

    Args:
        header_block: The full header block to process.
        which_hdrs: Headers to extract addresses from (e.g., 'From', 'To').
        db_handle: The database object.
        args: Command-line arguments.
    """
    for line in header_block.splitlines():
        # Decode each line in case it's encoded
        decoded_line = decode_email_header(line)

        # Check if the line starts with one of the desired headers
        for hdr in which_hdrs:
            if decoded_line.startswith(hdr + ":"):
                addr = parseaddr(decoded_line)[1]
                if debugging:
                    print(f"Extracted address: {addr}")
                if addr:
                    if args.check:
                        if db_access('query', db_handle, addr):
                            if debugging:
                                print(f"Address {addr} found in DB.")
                            sys.exit(0)
                        else:
                            if debugging:
                                print(f"Address {addr} not found in DB.")
                            sys.exit(1)
                    else:
                        db_access('update', db_handle, addr, args.strict)
                break  # Stop searching headers in this line if we found an address

if __name__ == '__main__':
    main()

