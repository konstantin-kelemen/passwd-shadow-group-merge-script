A Perl script that carefully merges the /etc/passwd, /etc/shadow, and /etc/group files, verifies the UID and GID mismatch, generates rsync strings for usermap and groupmap and also merges the password hashes from sender's /etc/shadow with the same file on the receiver.
