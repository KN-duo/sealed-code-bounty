#!/bin/sh
# Print the flag once per connection, then echo stdin back until EOF.
cat /flag
echo
exec cat
