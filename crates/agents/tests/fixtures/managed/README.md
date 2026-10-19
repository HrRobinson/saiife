# Managed agent config fixtures

These are the managed files `saiife system install` will write (plan 9), copied
byte-for-byte from spec section 8.3 (Gemini without the hooks on/off key; a later
recording adds it). `scripts/live-check-locked.sh` verifies them live against the
real agents inside a container. Recorded results live in `../lock-check/`.
