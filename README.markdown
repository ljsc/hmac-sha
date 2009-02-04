= hmac-sha

** A Pure Haskell Implementation of HMAC. **

This library builds on top of [Data.Digest.Pure.SHA][Pure-SHA] to implement
[Keyed-Hash Message Authentication Code][HMAC]s (HMAC).  This will allow
you to calculate HMACs without needing to bind to an external
library such as OpenSSL.

[Pure-SHA]: <http://hackage.haskell.org/cgi-bin/hackage-scripts/package/SHA> "Data.Digest.Pure.SHA"
[HMAC]:     <http://en.wikipedia.org/wiki/Hmac> "HMAC"

