import { connect } from 'cloudflare:sockets'
import { Protocol } from '../constants/protocol'
import { safeCloseWebSocket } from '../utils/helpers'
import type { Header } from '../protocols/index'

async function retry(
  version: number,
  rawData: ArrayBuffer,
  ws: WebSocket,
  proxyIPs: string[],
): Promise<Socket | undefined> {
  for (const proxyIP of proxyIPs) {
    try {
      const socket = await dial(proxyIP, version, rawData, ws)
      return socket
    } catch (err) {
      console.error(err)
      continue
    }
  }
}

async function dial(
  remote: SocketAddress | string,
  version: number,
  rawData: ArrayBuffer,
  ws: WebSocket,
): Promise<Socket> {
  let messageFn = null
  let closeFn = null
  let errorFn = null
  try {
    const socket = connect(remote)
    const writer = socket.writable.getWriter()
    await writer.write(rawData)
    messageFn = async (event: MessageEvent) => {
      await writer.write(event.data)
    }
    closeFn = async () => {
      await socket.close()
    }
    errorFn = async () => {
      await socket.close()
    }
    ws.addEventListener('message', messageFn)
    ws.addEventListener('close', closeFn)
    ws.addEventListener('error', errorFn)

    const reader = socket.readable.getReader()
    const { done, value } = await reader.read()
    if (done) {
      throw Error('connection was done')
    }
    reader.releaseLock()
    ws.send(
      await new Blob([Protocol.RESPONSE_DATA(version), value]).arrayBuffer(),
    )
    return socket
  } catch (err) {
    if (messageFn) {
      ws.removeEventListener('message', messageFn)
    }
    if (closeFn) {
      ws.removeEventListener('close', closeFn)
    }
    if (errorFn) {
      ws.removeEventListener('error', errorFn)
    }
    throw err
  }
}

export async function processTCP(
  ws: WebSocket,
  header: Header,
  proxyIPs: string[],
) {
  let socket: Socket | undefined
  try {
    // Preserve the original hostname (domain) for TLS SNI.
    // Let the socket implementation perform DNS lookups so SNI and TLS handshakes use the correct server name.
    const originalAddress = header.address
    let address = originalAddress
    if (isNaN(Number(address.split('.')[0]))) {
      // This looks like a domain name; attempt to resolve for logging/metrics
      try {
        const resolved = await resolveDomain(address)
        // If resolution succeeded, keep the resolved IP available but continue to use the original hostname for connect
        if (resolved && resolved !== address) {
          address = resolved
        }
      } catch (resolveErr) {
        console.error(`Failed to resolve domain ${address}:`, resolveErr)
        // Fall back to original address
      }
    }

    // Log which hostname/IP we will attempt to connect to and which hostname we'll use for SNI
    console.info(`connecting to host: ${address} (SNI: ${originalAddress})`)

    // Use the original hostname for the connect call so the TLS SNI is preserved.
    socket = await dial(
      { hostname: originalAddress, port: header.port },
      header.version,
      header.rawData,
      ws,
    )
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
  } catch (_) {
    socket = await retry(header.version, header.rawData, ws, proxyIPs)
  }
  if (socket === undefined) {
    throw Error(
      `cannot connect to hostname: ${header.address}, port: ${header.port}`,
    )
  }
  await socket.readable.pipeTo(
    new WritableStream({
      write(chunk) {
        ws.send(chunk)
      },
      abort() {
        safeCloseWebSocket(ws)
      },
      close() {
        safeCloseWebSocket(ws)
      },
    }),
  )
}

// Add domain resolution function
async function resolveDomain(domain: string): Promise<string> {
  // Try to resolve the domain using DNS over HTTPS (prefer A, then AAAA)
  try {
    async function doh(type: 'A' | 'AAAA'): Promise<string | null> {
      const response = await fetch(
        `https://cloudflare-dns.com/dns-query?name=${domain}&type=${type}`,
        { headers: { 'Accept': 'application/dns-json' } },
      )
      if (!response.ok) return null
      const data: any = await response.json()
      if (data.Answer && data.Answer.length > 0) {
        // Prefer the matching record type
        const wantedType = type === 'A' ? 1 : 28
        const rec = data.Answer.find((record: any) => record.type === wantedType)
        if (rec) return rec.data
        // Otherwise return the first answer available
        return data.Answer[0].data
      }
      return null
    }

    const a = await doh('A')
    if (a) return a
    const aaaa = await doh('AAAA')
    if (aaaa) return aaaa
  } catch (err) {
    console.error('DNS resolution error:', err)
  }

  // Fallback to the original domain if resolution fails
  return domain
}
