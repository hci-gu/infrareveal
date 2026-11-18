import { networkInterfaces, platform } from 'node:os'
import { lookup } from 'node:dns/promises'
import { isIP } from 'node:net'
import { command } from './process.mjs'

export function parseRoute(text) {
  const field = name => text.match(new RegExp(`^\\s*${name}:\\s*(\\S+)`, 'm'))?.[1]
  return { gateway: field('gateway'), interface: field('interface') }
}

export function requireGateway(route, gateway, iface) {
  if (route.gateway !== gateway || !route.interface || (iface && route.interface !== iface)) {
    throw new Error(`Traffic would bypass the Pi: gateway=${route.gateway || 'none'}, interface=${route.interface || 'none'}; expected ${gateway}${iface ? ` on ${iface}` : ''}`)
  }
}

export async function routeTo(destination) {
  const result = await command('/sbin/route', ['-n', 'get', '-inet', destination])
  if (result.code !== 0) throw new Error(`Cannot inspect route to ${destination}: ${result.stderr}`)
  return { destination, ...parseRoute(result.stdout) }
}

export async function guardRoute(gateway, iface) {
  if (platform() !== 'darwin') throw new Error('Gateway route validation currently supports macOS. Use --local-only for loopback development tests.')
  const route = await routeTo('1.1.1.1')
  requireGateway(route, gateway, iface)
  return route
}

export function publicIPv4(ip) {
  if (isIP(ip) !== 4) return false
  const value = ip.split('.').reduce((sum, octet) => sum * 256 + Number(octet), 0)
  return !['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12',
    '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/3']
    .some(cidr => { const [base, length] = cidr.split('/'); const size = 2 ** (32 - Number(length)); const network = base.split('.').reduce((sum, octet) => sum * 256 + Number(octet), 0); return Math.floor(value / size) === Math.floor(network / size) })
}

export async function preflight(plan) {
  const curl = await command('curl', ['--version'])
  if (curl.code !== 0) throw new Error('curl is required')
  const evidence = { at: new Date().toISOString(), platform: platform(), curl: curl.stdout.split('\n')[0], mode: plan.localOnly ? 'loopback-only, not gateway evidence' : 'Pi gateway', warnings: [] }
  if (plan.localOnly) return evidence
  const route = await guardRoute(plan.gateway)
  evidence.route = route
  evidence.addresses = (networkInterfaces()[route.interface] || []).filter(a => a.family === 'IPv4').map(a => a.address)
  if (!evidence.addresses.length) throw new Error(`No IPv4 address on ${route.interface}`)
  const dns = await command('/usr/sbin/scutil', ['--dns'])
  const primary = dns.stdout.split('resolver #1')[1]?.split(/resolver #\d+/)[0] || ''
  evidence.primaryDNS = [...primary.matchAll(/nameserver\[\d+\]\s*:\s*(\S+)/g)].map(match => match[1])
  if (!evidence.primaryDNS.length || evidence.primaryDNS.some(ip => ip !== plan.gateway)) {
    throw new Error(`Use the Pi as the Mac's primary DNS resolver for this run (found ${evidence.primaryDNS.join(', ') || 'none'}). Browser encrypted DNS is disabled by this harness.`)
  }
  evidence.targets = []
  for (const hostname of new Set(plan.clients.flatMap(c => c.profile.urls.map(url => new URL(url).hostname)))) {
    const addresses = await lookup(hostname, { family: 4, all: true })
    for (const { address } of addresses) {
      if (!publicIPv4(address)) throw new Error(`${hostname} resolves to ${address}, which the Pi's live observer excludes. Use a public test destination, or --local-only for loopback tests.`)
      const targetRoute = await routeTo(address)
      requireGateway(targetRoute, plan.gateway, route.interface)
      evidence.targets.push({ hostname, address, route: targetRoute })
    }
  }
  evidence.warnings.push('Route checks cover the default path and configured targets, not every future browser subresource. Keep VPNs and alternate Internet routes disabled.')
  return evidence
}

export async function resolveFrom(hostname, sourceIP, server, { signal, port = 53 } = {}) {
  if (isIP(sourceIP) !== 4 || isIP(server) !== 4 || isIP(hostname)) throw new Error('DNS probe needs IPv4 source/server addresses and a hostname URL')
  const result = await command('dig', ['-4', '-b', sourceIP, `@${server}`, '-p', String(port), hostname, 'A', '+time=3', '+tries=1', '+noall', '+answer', '+comments'], { signal, timeout: 5000 })
  if (result.code !== 0 || !/status: NOERROR/.test(result.stdout)) throw new Error(`DNS from ${sourceIP} failed: ${result.stderr || result.stdout}`)
  const addresses = [...result.stdout.matchAll(/^\S+\s+\d+\s+IN\s+A\s+(\S+)\s*$/gm)].map(match => match[1]).filter(ip => isIP(ip) === 4)
  if (!addresses.length) throw new Error(`No IPv4 DNS answers for ${hostname} from ${sourceIP}`)
  return { hostname, sourceIP, server, addresses }
}

export function requireSources(sourceIPs, iface) {
  if (sourceIPs.length < 2 || sourceIPs.length > 30 || new Set(sourceIPs).size !== sourceIPs.length || sourceIPs.some(ip => isIP(ip) !== 4)) {
    throw new Error('Provide 2–30 distinct IPv4 addresses with --source-ips')
  }
  const assigned = (networkInterfaces()[iface] || []).filter(a => a.family === 'IPv4').map(a => a.address)
  for (const ip of sourceIPs) if (!assigned.includes(ip)) throw new Error(`${ip} is not configured on ${iface}; this tool does not add IP aliases`)
}
