# flootty

## Development status: Works on Linux/OsX (Cygwin is untested).  

Flootty is a collaborative terminal. In practice, it's similar to a shared screen or tmux session.


## Installation

	pip install flootty

If you prefer, you can clone the git repo and run:

    python setup.py install


## Configuration

Add your Floobits username and API secret to `~/.floorc`. The format is newline-delimited key-space-value. A typical floorc looks like this:

    username myuser
    secret gii9Ka8aZei3ej1eighu2vi8D


## Usage

To create a shared terminal:

    flootty --owner=myuser --room=myroom --create example_terminal

To join that terminal:

    flootty --owner=myuser --room=myroom example_terminal

Flootty will automatically attempt to join a room without specifying the term name if there is only one terminal.
Flootty is also able to read metadata in .floo files which floobits adds to the root directory of every shared room.  Simply call flootty from a shared directory.

Edit permissions in a room are required to join a flooty and admin permissions are required to write to one.

To avoid confusion, your terminal's prompt is prepended with the owner, room name, and terminal name.
