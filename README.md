# flootty

## Development status: Works on Linux/OsX (Cygwin is untested).

Flootty is a collaborative terminal. In practice, it's similar to a shared screen or tmux session.
Flootty makes it dead simple for multiple users to share a shell.
We also added a pty to our browser based editor for those without a terminal.


## Installation

    pip install Flootty

If you prefer, you can clone the git repo and run:

    python setup.py install


## Configuration

First thing, you need a [floobits](https://floobits.com/) account.  Then, add your Floobits username and API secret to `~/.floorc`. The format is newline-delimited key-space-value. A typical floorc looks like this:

    username myuser
    secret gii9Ka8aZei3ej1eighu2vi8D


## Usage

To create a shared terminal:

    flootty --owner=myuser --workspace=myworkspace --create example_terminal

To join that terminal:

    flootty --owner=myuser --workspace=myworkspace example_terminal

Flootty will automatically attempt to join a workspace without specifying the term name if there is only one terminal.
Flootty is also able to read metadata in .floo files which floobits adds to the root directory of every shared workspace.  Simply call flootty from a shared directory.

Edit permissions in a workspace are required to join a flooty and admin permissions are required to write to one.

To avoid confusion, your terminal's prompt is prepended with the owner, workspace name, and terminal name.
