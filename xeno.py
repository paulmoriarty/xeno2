#!/usr/bin/env python3

import os
import bsddb3 as db  # For Berkeley DB compatibility
from email.utils import parseaddr
from email_validator import validate_email, EmailNotValidError
import argparse

# GLOBAL
debugging = False
dbfile = ""

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
            print(f"Invalid email: {e}")
            return

    if action == 'update':
        if strict and '@' not in key:
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
    which_hdrs = ['From'] if args.check else ['To', 'From']

    headers = []
    in_hdr = False

    for line in sys.stdin:
        line = line.rstrip()

        if not in_hdr and line.startswith('From '):
            in_hdr = True
            headers = []

        if in_hdr:
            if line == '':
                in_hdr = False
                process_header("\n".join(headers), which_hdrs, db_handle, args)
            else:
                if line.startswith(" "):  # Continuation of the previous line
                    headers[-1] += line
                else:
                    headers.append(line)

def process_header(header, which_hdrs, db_handle, args):
    """Extract and process addresses from a header line.

    Args:
        header: The e-mail header line.
        which_hdrs: List of headers to extract ('From', 'To', etc.).
        db_handle: The database object.
        args: Command-line arguments.
    """
    if any(h in header for h in which_hdrs):
        addr = parseaddr(header)[1]
        if debugging:
            print(f"Stripped address:\n  {addr}\n")
        if args.check:
            if db_access('query', db_handle, addr):
                if debugging:
                    print(f"I know this address\n")
                sys.exit(0)
            else:
                if debugging:
                    print(f"I DON'T KNOW this address\n")
                sys.exit(1)
        else:
            db_access('update', db_handle, addr, args.strict)

if __name__ == '__main__':
    main()

