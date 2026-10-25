# security

Changing the User-Agent header on every request got around the sign-in rate
limit.

The limit shared by sign-in, the emailed sign-in link, the GitHub callback,
invitations and the operator portal kept one bucket per address and user agent.
The user agent is whatever the caller sends, so a new one on each request was a
new bucket on each request, the same way a forged X-Forwarded-For entry was
before it was fixed. The bucket is now the address alone. Each of those routes
also had its own per-address limit, which still held, so this took away the
shared limit across them rather than every limit.

People who share one address, an office behind one NAT for example, now share
that limit too, as they already shared each route's own limit.
