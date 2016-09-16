# kget
## Simple Kerberos Testing Utility

- Obtain an initial ticket
- Use this initial ticket to obtain a service ticket from the KDC

Use as e.g.

   `kget principal host/hostname`

to obtain a ticket granting ticket (`krbtgt`) for `principal` and than use that to obtain a service ticket for `host/hostname`.

In the future may become a full-fledged C++ wrapper for the heimdal kerberos libraries.
