# fixed

A control plane run from a directory with a space in its path served no
console.

With AF_CONSOLE_DIR unset, the control plane finds the console build from where
its own source sits, and it read that location without decoding it. Under
`~/My Projects/antifailure` it looked for the build in `My%20Projects`, found
nothing, logged NO CONSOLE BUILD and answered every page by saying so. On
Windows the same path began `/C:/`. The location is now decoded, so the build
beside the source is found. The published image runs from `/app` and was never
affected.
