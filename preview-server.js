// Dependency-free local preview for the VisionON front-end prototype.
// The full API server is server.js and requires npm dependencies plus PostgreSQL.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const root = __dirname;
const files = new Map([
  ['/', ['index.html', 'text/html; charset=utf-8']],
  ['/index.html', ['index.html', 'text/html; charset=utf-8']],
  ['/styles.css', ['styles.css', 'text/css; charset=utf-8']],
  ['/app.js', ['app.js', 'text/javascript; charset=utf-8']]
]);
http.createServer((req, res) => {
  const entry = files.get(new URL(req.url, 'http://localhost').pathname);
  if (!entry) { res.writeHead(404); return res.end('Not found'); }
  res.writeHead(200, { 'Content-Type': entry[1], 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store' });
  fs.createReadStream(path.join(root, entry[0])).pipe(res);
}).listen(4173, '127.0.0.1', () => console.log('VisionON preview at http://127.0.0.1:4173'));
