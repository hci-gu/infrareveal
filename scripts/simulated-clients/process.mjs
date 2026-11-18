import { spawn } from 'node:child_process'

// No shell interpolation, inherited proxy settings, or unbounded child output.
export function command(file, args, { signal, input, timeout = 10000 } = {}) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new Error('cancelled'))
    const child = spawn(file, args, { stdio: ['pipe', 'pipe', 'pipe'] })
    let stdout = '', stderr = '', error, killer
    const stop = () => { child.kill('SIGTERM'); killer ??= setTimeout(() => child.kill('SIGKILL'), 1000); killer.unref() }
    const timer = setTimeout(() => { error = new Error(`${file} timed out`); stop() }, timeout)
    const abort = () => { error = new Error('cancelled'); stop() }
    signal?.addEventListener('abort', abort, { once: true })
    child.stdout.on('data', data => {
      stdout += data
      if (stdout.length > 2 * 1024 * 1024) { error = new Error(`${file} output exceeded its limit`); stdout = stdout.slice(0, 2048); stop() }
    })
    child.stderr.on('data', data => { stderr = (stderr + data).slice(-8192) })
    child.stdin.on('error', () => {}) // curl can reject a request before reading its upload.
    child.on('error', e => { error = e })
    child.on('close', (code, childSignal) => {
      clearTimeout(timer); clearTimeout(killer); signal?.removeEventListener('abort', abort)
      if (error) reject(error)
      else resolve({ code, signal: childSignal, stdout, stderr })
    })
    child.stdin.end(input)
  })
}

export function sleep(ms, signal) {
  return new Promise(resolve => {
    if (signal?.aborted) return resolve()
    const done = () => { clearTimeout(timer); signal?.removeEventListener('abort', done); resolve() }
    const timer = setTimeout(done, ms)
    signal?.addEventListener('abort', done, { once: true })
  })
}

export async function transfer(url, profile, { signal, sourceIP, resolvedIP } = {}) {
  const target = new URL(url)
  const args = ['-q', '--ipv4', '--noproxy', '*', '--silent', '--show-error', '--fail-with-body', '--proto', '=http,https',
    '--connect-timeout', String(Math.min(10, profile.timeoutSeconds)), '--max-time', String(profile.timeoutSeconds),
    '--output', '/dev/null', '--write-out', '%{json}', '--limit-rate', String(profile.rateBytesPerSecond)]
  if (sourceIP) args.push('--interface', sourceIP)
  if (resolvedIP) args.push('--resolve', `${target.hostname}:${target.port || (target.protocol === 'https:' ? 443 : 80)}:${resolvedIP}`)
  if (profile.kind === 'upload') args.push('--request', 'POST', '--header', 'Content-Type: application/octet-stream', '--data-binary', '@-')
  args.push('--url', url)
  const result = await command('curl', args, { signal, timeout: (profile.timeoutSeconds + 2) * 1000,
    input: profile.kind === 'upload' ? Buffer.alloc(profile.uploadBytes, 120) : undefined })
  let data
  try { data = JSON.parse(result.stdout) } catch { throw new Error(`curl did not return metrics: ${result.stderr || result.stdout}`) }
  return { ok: result.code === 0 && data.http_code >= 200 && data.http_code < 300,
    status: data.http_code, exitCode: result.code, error: result.stderr.trim() || undefined,
    localIP: data.local_ip, remoteIP: data.remote_ip, protocol: data.http_version,
    receivedBytes: data.size_download, sentBytes: data.size_upload, elapsedMs: data.time_total * 1000,
    dnsMs: data.time_namelookup * 1000, connectMs: data.time_connect * 1000, tlsMs: data.time_appconnect * 1000,
    firstByteMs: data.time_starttransfer * 1000 }
}
