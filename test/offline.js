'use strict';

const net = require('net');
const tls = require('tls');
const http = require('http');
const https = require('https');
const dns = require('dns');

function refuse() {
  const e = new Error('network access is disabled while testing the command line');
  e.code = 'ENETUNREACH';
  throw e;
}

for (const mod of [net]) {
  mod.connect = refuse;
  mod.createConnection = refuse;
  mod.Socket.prototype.connect = refuse;
}
tls.connect = refuse;
for (const mod of [http, https]) {
  mod.request = refuse;
  mod.get = refuse;
}
dns.lookup = refuse;
dns.resolve = refuse;
if (dns.promises) {
  dns.promises.lookup = async () => refuse();
  dns.promises.resolve = async () => refuse();
}
globalThis.fetch = async () => refuse();
