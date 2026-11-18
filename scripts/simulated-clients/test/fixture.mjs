import http from 'node:http'
import { mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'

export async function fixture() {
  const requests = []
  const server = http.createServer((req, res) => {
    const row = { url: req.url, method: req.method, bytes: 0, source: req.socket.remoteAddress, cookie: req.headers.cookie }
    requests.push(row)
    req.on('data', data => { row.bytes += data.length })
    req.on('end', () => {
      if (req.url === '/hang') return
      if (req.url === '/fail') { res.writeHead(503); res.end('unavailable'); return }
      if (req.url === '/redirect') { res.writeHead(302, { Location: 'https://example.com/escape' }); res.end(); return }
      if (req.url === '/page') {
        res.writeHead(200, { 'Content-Type': 'text/html', 'Set-Cookie': 'fixture=visited; Path=/', 'Cache-Control': 'no-store' })
        res.end('<!doctype html><html><head><title>Simulator fixture</title></head><body style="height:3000px"><h1>Controlled browsing fixture</h1><img src="/asset"><script>fetch("/status")</script></body></html>')
        return
      }
      res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Cache-Control': 'no-store' })
      res.end(Buffer.alloc(req.url === '/download' ? 8192 : 32, 120))
    })
  })
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  const directory = await mkdtemp(join(tmpdir(), 'ir-client-simulator-'))
  const origin = `http://127.0.0.1:${server.address().port}`
  return { origin, requests, directory, close: async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)) },
    scenario: async (profiles) => { const path = join(directory, 'scenario.json'); await writeFile(path, JSON.stringify({ version: 1, name: 'loopback fixture', profiles })); return path } }
}

export function cli(args) {
  const child = spawn(process.execPath, [fileURLToPath(new URL('../cli.mjs', import.meta.url)), ...args], { stdio: ['ignore', 'pipe', 'pipe'] })
  let stdout = '', stderr = ''
  child.stdout.on('data', data => { stdout += data })
  child.stderr.on('data', data => { stderr += data })
  const done = new Promise((resolve, reject) => {
    const timeout = setTimeout(() => { child.kill('SIGKILL'); reject(new Error(`CLI hung: ${stdout} ${stderr}`)) }, 45000)
    child.on('error', error => { clearTimeout(timeout); reject(error) })
    child.on('close', (code, signal) => { clearTimeout(timeout); resolve({ code, signal, stdout, stderr }) })
  })
  return { child, done }
}
