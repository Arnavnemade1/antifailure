# fixed

A plus address written in two cases was masked to two different addresses.

The email transform masks `Person@Example.com` and `person@example.com` to the
same address, because they are the same mailbox. The tag it keeps for a plus
address was worked out from the address as written, so `Person+News@` and
`person+news@` came out with the same local part and different tags. A join on
email between a table that keeps the address as typed and one that keeps it
lowercased stopped matching for every plus address in the masked copy.

The tag now comes from the same lowercased, trimmed address as the rest. An
address that was already lowercase with no surrounding space masks exactly as
it did; a plus address with a capital letter or surrounding space masks to a
new value, once, and to the same value as its lowercase form from then on.
