# flootty

## Development status: Working, but still a little buggy.

Flootty is a collaborative terminal. In practice, it's similar to setting up a shared screen or tmux session.


## Installation

TODO


## Configuration

Add your Floobits username and API secret to `~/.floorc`. The format is newline-delimited key-space-value. A typical floorc looks like this:

    username myuser
    secret gii9Ka8aZei3ej1eighu2vi8D


## Usage

To create a shared terminal:

    python flootty.py --owner=myuser --room=myroom --create=example_terminal

To join that terminal:

    python flootty.py --owner=myuser --room=myroom --join=example_terminal


To avoid confusion, your terminal's prompt is prepended with the owner, room name, and terminal name.
