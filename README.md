# Dependencies

* python2
* pycrypto

# Use

`attack2des` takes an optionel key length as first command line
argument; it expects a sequence of (hex) plain text and cipher text
pairs on stdin, one per line; it outputs all key1 and key2 pairs it
finds (separated by a space) on stdout.  For example:

```bash
$ cat > set8
0123456789ABCDEF
8dc1e5170cb054e0
1122334455667788
b91d899c5007f514
99aabbccddeeff00
6b71df6c17ae286f
^D

$ ./attack2des < set8 2>/dev/null
0101010107cd37b9 010101010b9d4667
0101010107cd37b9 010101010b9d4667
0101010107cd37b9 010101010b9d4667
```
