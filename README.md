The Treyfer cypher is a block cipher designed in 1997 by Gideon Yuval for use on embedded devices. The algorithm is simple and compact and it can be implemented in a few code lines.

Not being designed for environments that require heavy cryptographic capabilities, the Treyfer lends itself well to being used as a fast cipher where medium/low level security is not required: the data block and the key are in fact 64 bits long each.

This implementation of the algorithm is based on Lua 5.4.
