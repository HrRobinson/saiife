# Data Shield

Data Shield lets people ask questions about a sensitive dataset (a customer
table, a ledger) and get exact answers, while the cloud model that plans the
work sees only the structure of the data and never a real personal value. This
page covers stage 1: exact mode, `saiife blind`, on Linux only.

## What it does

You ask "What does Anna Berg owe, and is she over her limit?". saiife takes the
name out of the question and resolves it on this machine to a customer record.
A cloud model (Claude, with your API key) gets the shape of the question and
writes a method: a read-only query. saiife checks the method, shows it to you
in plain words, and runs it only when you say so. A sandboxed local calculator
runs it on a read-only copy of the data. The answer is filled in from what the
calculator produced and then checked: any number that the calculator did not
produce refuses the whole answer.

## Guarantees and their limits

- **G1. No real personal value leaves this machine** unless a person approved
  it with a touch, and the approval is in the audit log. In stage 1 there is
  one such path, `blind:name`: a person's name in your question that is not
  in the dataset (an outsider) can be kept. `ask` then asks
  `"<name>" is not in <dataset>. Send it as plain text to the planner? This needs a touch (blind:name). (y/N)`.
  The touch shows the exact name. After it, the name is sent to the planner
  as plain text, and it stays released for the rest of the session: later
  questions in that session send it too. The audit log records the release
  by a keyed hash of the name, never the name. Without that touch no real
  value is sent.
- **G2. Numbers in exact mode are exactly what the shown method computes on
  the real data.** No number is made up, mistyped or rounded wrong. G2 does
  not promise that the method answers the question you meant: a valid method
  can still answer the wrong question. That is why the method is shown in plain
  words before it runs and again in the answer, and why an approver can approve
  a method once for reuse.
- **G3. Everything that left is documented.** Every body sent to the planner is
  in the audit log by sha256, and the exact bytes are kept in a local outbox.

Honest limits:

- Judgment questions ("is this customer a churn risk?") have no exact answer.
  Stage 1 does not answer them.
- Pseudonymized data is still personal data under GDPR (Art. 4(5), Recital 26).
  Stand-ins reduce risk; they do not make data anonymous. You still need a
  legal basis, a data processing agreement with the AI provider and, at scale,
  most likely a DPIA. saiife never claims anonymization.
- Free text is never reliably free of personal data, so exact mode never sends
  it.
- The name detector is never perfect. A name it misses that is also not in the
  dataset could be sent as plain text in the stripped question. The firewall
  still blocks every value that is in the dataset.
- The shape of a question can leak ("which customer in Tromsø over 90 owes the
  most?"). k-guard bounds this; it does not remove it.
- The calculator is a sandboxed process (Landlock, no sockets), not a box yet.
  `saiife blind status` and every run record say so with the label
  "calculator not in a box (weaker)".

## What leaves in exact mode

The planner gets, and nothing else:

- the schema: table and column names (or aliases you set), types, classes and
  row counts as bands ("about 3 million");
- stand-in symbols;
- the question with every name, ID and literal replaced by a typed parameter
  ("what does customer `:p1` (a customer key) owe, and is it over `:p2` (an
  amount)?");
- category values from columns you marked `public`, only those that occur in at
  least k records;
- a few synthetic sample rows built from the schema and the column classes,
  never from real rows.

`saiife blind ask --show-sent` prints the exact request. Nothing from a
sensitive, quasi-identifier or free-text column is sent, not even as fiction.
Names, IDs and amounts are never `public`.

## Setting up

`saiife blind init` has six steps: Data, Columns, Models, Cloud, Rules, Test.
Every step has a flag, so a script can run it.

```
saiife blind init --dataset sales --file customers.csv \
  --entity customers:id:first_name+last_name:city:customer:kunde \
  --users group:sales --approvers anna \
  --ner-model-url https://… --ner-model-sha256 … \
  --ner-vocab-url … --ner-vocab-sha256 … --ner-labels-url … --ner-labels-sha256 … \
  --cloud-secret anthropic --yes
```

- **Data.** A csv, xlsx or sqlite file, or a Postgres on this machine (a unix
  socket directory or loopback). A Postgres on another host is refused.
- **Columns.** The classifier proposes a class for every column (identifier,
  quasi, sensitive, free_text, public); you accept or change them
  (`--accept-guesses`, `--class table.column=class`, `--public`, `--alias`).
  `--entity` names the table people are looked up in; `--identifier` names the
  column that identifies the person in a table.
- **Models.** The name detector (below) is fetched and checked against the
  sha256 you pinned; the download shows its progress once a second. `init` and `ask` refuse until model, vocabulary and labels
  are pinned.
- **Cloud.** The planner's key is an API key in the saiife vault (`--cloud-secret`).
  API keys only: there is no subscription login.
- **Rules.** The line reads "exact mode by default · k = 10 · preview before
  every run · English, Danish". With `--preview-required` off it reads "preview
  before every run unless --yes".
- **Test.** A question built from the schema, to show the whole path works
  (`--skip-test` leaves it out, `--show-sent` prints the request).

A dataset build refuses an entity key with repeated or empty values: a key must
identify one record.

`init` and `saiife blind data add` keep an existing dataset's settings, and
refuse to loosen k, users or approvers. That change needs a hand edit of the
policy file, then `saiife policy reload`. In locked mode `init` must run as root
(`sudo saiife blind init`), because the policy drop-in directory is root-owned.

## Asking

```
saiife blind ask "What does Anna Berg owe, and is she over her limit?" [--judgment]
    [--show-sent] [--dataset d] [--new-session] [--yes] [--limit n] [--lang en|da]
```

```
Found 2 customers named Anna Berg:
  1) Anna Berg, Aarhus
  2) Anna Berg, Odense
Which one? 1
I'm summing all invoices for Anna Berg, Aarhus with status 'open',
and comparing the total with her credit limit.
Run it? (Y/n) y

Anna Berg owes 18,420.00 NOK across 3 open invoices. That is above her limit of 15,000.00 NOK.
── method: summed all invoices for Anna Berg, Aarhus with status 'open'; compared with customers.credit_limit
── exact · method m-balance-v2 (approved) · 0 personal values sent · 3/3 numbers checked
```

The candidate list and the preview are shown on this machine only. They name
a record by its display name and the `show` columns that are not identifiers
(a city, say); never its key, and never an email, ID or phone number. When
two records share a name, the number in the list tells them apart.

A person's name that is not in the dataset is not sent by default. `ask`
offers to keep it as plain text, which takes a `blind:name` touch (see G1);
the name then stays released for the session. Answer no and the question is
refused, nothing sent.

The rest of the ask: Pick lists,
"did you mean" and the preview need a terminal; without one `ask` refuses (or,
for the preview, takes `--yes`). `--yes` is refused for a dataset that requires
the preview. A list answer is capped at 100 rows and says so ("showing 100 of
2,314") above the method line. A question about a customer with no matching
records is a refusal, never 0.

A refusal shows the refusal head, the reason and the method line. Exit codes: 0
answered, 2 refused (a refusal, stop, firewall block or checker), 5 unavailable
(daemon, vault, detector, Landlock, dataset refreshing or still opening, or not
Linux).

Exact mode never prints Identifier values. A method that would print one (an ID
number, say) is refused with the code `identifier_output` and the reason "Data
Shield doesn't show ID numbers. Revealing one needs a touch on your key." The
touch-gated reveal comes in a later release.

## Approved methods

After an answered ask, an approver can approve its method for reuse:

```
saiife blind methods approve <ask-id>     # approver role and a touch (blind:approve)
saiife blind methods ls
saiife blind methods rm <id>              # approver role and a touch
```

The same question template with the same parameter types then runs the stored
method with no cloud call at all; the preview is still shown. `methods approve`
refuses methods that kept a name or that use the session context. Approvers see
the hint "approve this method for reuse: saiife blind methods approve <ask-id>"
after an answer. Only on the local socket.

## Other commands

```
saiife blind status [--json]                 # datasets, calculator label, name detector, cloud key, warnings
saiife blind audit [--since 7d] [--user u] [--sent <sha256>] [--json]
saiife blind keys rotate [--dataset d]       # touch (blind:keys)
saiife blind keys delete --dataset d         # crypto-shredding, touch, you type the name
saiife blind data add
saiife blind data rm --dataset d             # crypto-shredding, touch (blind:keys), you type the name
saiife blind data refresh [--dataset d] [--file f]
saiife blind data class <dataset> <table.column> <class>
```

- `data refresh` rebuilds the dataset from its source, shows progress until it
  is live and re-validates the approved methods. Older datasets need it.
- `data class`: a stricter class is written to policy at once; a looser one
  takes a touch (blind:loosen) first. A move to `public` refuses names, IDs and
  amounts.
- `data rm` removes the snapshot, the keys and the approved methods. Deleting
  the keys is crypto-shredding, so it takes the same `blind:keys` touch as
  `keys delete`, after you type the dataset name.
- `audit --user` needs the auditor role (root or `saiife-audit`).

## Roles and touches

- **Users** may ask. **Approvers** also approve and remove methods. **Admins**
  manage keys and data. Roles come from the dataset's policy.
- Touches (a FIDO2 key, see [Touch approvals](touch.md)):
  - `blind:name`: keep an outsider's name as plain text in a question (the
    asker; see G1).
  - `blind:approve`: approve or remove a method.
  - `blind:keys`: rotate or delete keys, and `data rm`.
  - `blind:loosen`: make a column's class looser.

  `blind:reveal` and `blind:release` are never issued in stage 1.

## Files

Everything is under `<state>/blind/`, mode 0700 (files 0600). Each dataset has a
read-only snapshot, its index and its keys. `outbox/YYYY-MM.jsonl` holds the
exact bytes of every request to the planner, readable by root or the auditor
group (on a personal install, by the user the daemon runs as).

The audit log holds the parameterized question: names, IDs and literals are
replaced by stand-ins, and a name kept with `blind:name` is shown as
`[kept name]`. It never holds a real value or an answer's text. An answer is
recorded only as a keyed MAC (`answer_mac`, keyed with the dataset's own key),
not as a plain hash, so a guessed answer cannot be checked against the log. A
kept name is recorded the same way, by keyed hash.

## What stage 1 does not do

- No judgment mode and no local composer (a later stage).
- No Workspace Ask screen, no phone use.
- No calculator box; the calculator is a sandboxed process.
- No touch-gated reveal of Identifier values (a later release).
- No macOS or Windows host: those users ask the Linux server.
- No subscription login for the planner: API keys only.
- No Postgres on another host.

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
  covers English and Danish. saiife does not ship a model. `saiife blind init` and
  `saiife blind ask` refuse to use the name detector until `[blind.ner]` in your
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
