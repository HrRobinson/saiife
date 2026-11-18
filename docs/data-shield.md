# Data Shield

Data Shield keeps customer data out of the model's context. Plan 48 Task 7
writes the full page; this file holds the sections that earlier plans add.

## Name detector

Questions can name people ("What does Søren Kjærgaard owe us?"). The name
detector is a small local model that finds those names so Data Shield can
replace them before anything reaches the model. It runs on this machine only;
no text leaves it.

- **What it is.** `saiife-ner`, a separate, sandboxed helper binary. It reads
  one JSON request per line on stdin and answers with name spans on stdout. It
  has no network and writes no file. Its inference engine (tract) is linked
  into `saiife-ner` and the `saiife-shield-ner` crate only: the `saiife`
  binary never links tract, and CI checks that.
- **Where it lives.** The Linux deb and rpm install it at
  `/usr/libexec/saiife/saiife-ner` (root-owned, mode 0755). There is no
  helper in the tarballs, on macOS or on Windows yet.
- **The model is pinned.** The first-choice model is ScandiNER (int8), which
  covers English and Danish. saiife does not ship a model. `saiife init` and
  `saiife ask` refuse to use the name detector until `[blind.ner]` in your
  config pins the model, the vocabulary and the labels file, each by its
  sha256. The helper checks every hash before it parses a byte, and refuses
  to start on a mismatch.
