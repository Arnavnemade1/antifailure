# fixed

Pressing Ctrl-C did not stop install.sh, and what it said next blamed GitHub.

The installer's clean-up handler for Ctrl-C removed its temporary directory and
then let the script carry on with its next step. Pressed during the download, it
asked github.com again about a download that had not failed, then said github.com
had not delivered the build, and exited with status 1, so a script that ran the
installer could not tell it had been cancelled.

Ctrl-C and a termination signal now stop the installer at once, after removing
what it downloaded, and it exits by that signal the way a cancelled program does.
An upgrade interrupted part way still puts the previous runner and `af` back.
