#!/usr/bin/env node
// MCP test server for the live lock checks: one tool, touch_marker, that
// creates ${LOCKCHECK_MARKERS:-/work/project/markers}/<name>. The checks use
// it to see whether an agent's MCP tool calls pass through the managed hook
// and whether the MCP allow/deny settings stop the server.
//
// No dependencies. Newline-delimited JSON-RPC 2.0 over stdio: answers
// initialize, tools/list and tools/call, ignores notifications (no id).
// <name> must be 12 lowercase hex chars (a check's nonce); anything else is
// refused with a JSON-RPC error and nothing is created. It touches nothing
// else.
//
//   node /lockcheck/mcp-marker.js
'use strict';

const fs = require('fs');
const path = require('path');
const readline = require('readline');

const markers = process.env.LOCKCHECK_MARKERS || '/work/project/markers';
const NAME = /^[0-9a-f]{12}$/;

const TOOL = {
  name: 'touch_marker',
  description: 'Create the lock-check marker file with the given name.',
  inputSchema: {
    type: 'object',
    properties: { name: { type: 'string', description: '12 hex characters' } },
    required: ['name'],
  },
};

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + '\n');
}

function reply(id, result) {
  send({ jsonrpc: '2.0', id, result });
}

function fail(id, code, message) {
  send({ jsonrpc: '2.0', id, error: { code, message } });
}

function handle(msg) {
  const { id, method } = msg;
  const params = msg.params || {};
  switch (method) {
    case 'initialize':
      return reply(id, {
        protocolVersion: params.protocolVersion || '2025-06-18',
        capabilities: { tools: {} },
        serverInfo: { name: 'lockcheck', version: '1.0.0' },
      });
    case 'ping':
      return reply(id, {});
    case 'tools/list':
      return reply(id, { tools: [TOOL] });
    case 'tools/call': {
      if (params.name !== TOOL.name) {
        return fail(id, -32602, `unknown tool: ${params.name}`);
      }
      const name = (params.arguments || {}).name;
      if (typeof name !== 'string' || !NAME.test(name)) {
        return fail(id, -32602, 'name must be 12 lowercase hex characters');
      }
      try {
        fs.writeFileSync(path.join(markers, name), '');
      } catch (err) {
        return fail(id, -32603, `cannot create marker: ${err.message}`);
      }
      return reply(id, { content: [{ type: 'text', text: 'ok' }] });
    }
    default:
      return fail(id, -32601, `method not found: ${method}`);
  }
}

const rl = readline.createInterface({ input: process.stdin, terminal: false });
rl.on('line', (line) => {
  if (!line.trim()) return;
  let msg;
  try {
    msg = JSON.parse(line);
  } catch (err) {
    return fail(null, -32700, 'parse error');
  }
  if (msg === null || typeof msg !== 'object' || msg.id === undefined || msg.id === null) {
    return; // notification
  }
  handle(msg);
});
