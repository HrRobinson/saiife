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

### Preparing the model (owner recipe)

saiife does not ship or download a model, and ScandiNER on Hugging Face is not
ready to pin as it is: it ships `config.json` and `vocab.txt`, but no int8 ONNX
file and no `labels.json`. To build the three files:

1. Export the model to ONNX with `optimum` (token classification), then apply
   dynamic int8 quantization to the ONNX file. That file is the model.
2. Build `labels.json` (`{"id2label": {"0": "O", "1": "B-PER", ...}, "do_lower_case": ..., "max_len": 512, "inputs": [...], "strip_accents": ...}`;
   unknown keys are refused) from the `id2label` map in the model's `config.json`. List all three BERT
   inputs (`input_ids`, `attention_mask`, `token_type_ids`) in `inputs`. An
   uncased model needs `strip_accents: true` set explicitly; it is not implied
   by `do_lower_case`.
3. Use the model's `vocab.txt` as the vocabulary.
4. Pin the sha256 of all three files in `[blind.ner]`. The helper refuses a
   labels file with no `PER` label.

The helper cannot catch an out-of-memory condition or a stack overflow: either
aborts it, and `saiife` then treats a helper that dies before or after its
hello as "name detector unavailable".

On arm64 the helper probes the CPU features after Landlock is applied, so
tract may fall back to its generic kernels. Measure latency in the owner
smoke before relying on it.
