# fixed

A console path with a broken percent escape was answered as a server failure.

A request such as `/%` or `/%zz` reached the console's page lookup with an escape
nothing could decode, the lookup threw, and the control plane answered 500. Any
scanner on the internet could produce those, and to a monitor they read as the
control plane failing. Such a path is now the console's own 404 page, like any
other page that does not exist.
