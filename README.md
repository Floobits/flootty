# flootty

## Development status: Works on Linux/OS X (Cygwin is untested).

Flootty is a collaborative terminal. In practice, it's similar to a shared screen or tmux session.
Flootty makes it dead simple for multiple users to share a shell.
We also added a pty to our browser based editor for those without a terminal.

[![PyPI version](https://badge.fury.io/py/flootty.svg)](http://badge.fury.io/py/flootty)


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

    flootty --create --url=https://floobits.com/owner/workspace

or...

    flootty --owner=myuser --workspace=myworkspace --create example_terminal

By default any guests won't be allowed to press Enter to execute a command. This is done for extra security when you don't want other people corrupting your system.
If you trust the person you are gonna work with use --unsafe option:
    
    flootty --owner=myuser --workspace=myworkspace --create example_terminal --unsafe

To join a terminal:

    flootty --url=https://floobits.com/owner/workspace example_terminal

or...

    flootty --owner=myuser --workspace=myworkspace example_terminal

If there is only one terminal in the workspace, there's no need no specify a name. Flootty will automatically attempt to join it. If the current directory contains a `.floo` file (because you shared that directory using a Floobits plugin), Flootty will allow you to omit the URL, owner, and workspace options.

You must have permission to edit a workspace to join someone else's terminal. You must have admin permissions to write to someone else's terminal.

To avoid confusion, your terminal's prompt is prepended with the owner, workspace name, and terminal name.
