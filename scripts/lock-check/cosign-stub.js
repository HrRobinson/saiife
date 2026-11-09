#!/usr/bin/env node
// Stand-in co-signer for the live lock checks (docs/lock-check.md, plan 20).
//
// Since plan 20 the Claude Code managed drop-in has a second PreToolUse hook,
// an HTTP hook to http://127.0.0.1:7433/v1/cosign/claude with
// `onFailure: "block"`. The checks run a stub, not the saiife daemon, so
// without this nothing listens there and Claude Code blocks every tool call.
// This answers every `POST /v1/cosign/claude` with `200` and an empty body:
// "no opinion" to Claude Code, so the stub saiife's verdict decides each row,
// as before plan 20. It says nothing about the real co-signer; CI's locked-*
// jobs test that against the real daemon.
//
// No dependencies. Started and stopped by lib.sh (lc_cosign_start and
// lc_cosign_stop), never by hand:
//
//   node cosign-stub.js <run dir> [port]
//
// It listens on 127.0.0.1:<port> (default 7433; 0 picks a free port, for the
// offline tests) and then writes <run dir>/cosign.ready holding the port. A
// failed listen (the port is taken, for example by an installed saiife)
// writes <run dir>/cosign.failed with the error and exits 1. Each request is
// one line in <run dir>/cosign.log: method, path and status. Any other method
// or path gets 404.
//
// It stops by itself, so the harness never signals it: when
// <run dir>/cosign.run is gone (lc_cosign_stop removes it; the harness's own
// cleanup removes the whole dir), or when its parent process has gone (the
// harness died; not detectable on Windows, where the run file still works).
// It touches nothing outside <run dir>.
'use strict';

const fs = require('fs');
const http = require('http');
const path = require('path');

const PATH = '/v1/cosign/claude';
const BODY_MAX = 64 * 1024 * 1024;
const POLL_MS = 200;

const runDir = process.argv[2];
const port = process.argv[3] === undefined ? 7433 : Number(process.argv[3]);
if (!runDir || !Number.isInteger(port) || port < 0 || port > 65535) {
  process.stderr.write('usage: node cosign-stub.js <run dir> [port]\n');
  process.exit(2);
}
const runFile = path.join(runDir, 'cosign.run');
const logFile = path.join(runDir, 'cosign.log');
const parent = process.ppid;

function log(line) {
  try {
    fs.appendFileSync(logFile, line + '\n');
  } catch (err) {
    // The run dir is gone: the watch below stops the server.
  }
}

const server = http.createServer((req, res) => {
  let size = 0;
  req.on('data', (chunk) => {
    size += chunk.length;
    if (size > BODY_MAX) req.destroy();
  });
  req.on('end', () => {
    const url = (req.url || '').split('?')[0];
    const status = req.method === 'POST' && url === PATH ? 200 : 404;
    log(`${req.method} ${url} ${status}`);
    res.writeHead(status, { 'Content-Length': '0', Connection: 'close' });
    res.end();
  });
  req.on('error', () => {});
});

server.on('error', (err) => {
  try {
    fs.writeFileSync(path.join(runDir, 'cosign.failed'), `${err.message}\n`);
  } catch (e) {
    // Nothing more to say.
  }
  process.stderr.write(`cosign-stub: cannot listen on 127.0.0.1:${port}: ${err.message}\n`);
  process.exit(1);
});

server.listen(port, '127.0.0.1', () => {
  const bound = server.address().port;
  // Whole or not at all: the harness reads the port as soon as it exists.
  const ready = path.join(runDir, 'cosign.ready');
  fs.writeFileSync(`${ready}.tmp`, `${bound}\n`);
  fs.renameSync(`${ready}.tmp`, ready);
  const watch = setInterval(() => {
    const orphaned = process.platform !== 'win32' && process.ppid !== parent;
    if (orphaned || !fs.existsSync(runFile)) {
      clearInterval(watch);
      server.close();
      // Open keep-alive connections would hold close() back.
      if (server.closeAllConnections) server.closeAllConnections();
      setTimeout(() => process.exit(0), 50).unref();
    }
  }, POLL_MS);
});
