import { connect } from 'cloudflare:sockets'
import { safeCloseWebSocket } from '../utils/helpers'
import { Protocol } from '../constants/protocol'
import type { Header } from '../protocols/index'

export async function processDNS(ws: WebSocket, header: Header) {
  // First try UDP/53 to a public resolver for lower latency. If that fails, fall back to DoH.
  try {
    const socket = connect({ hostname: '8.8.8.8', port: 53 })
    const writer = socket.writable.getWriter()
    await writer.write(header.rawData)

    const handleMessage = async (event: MessageEvent) => {
      const data = event.data instanceof ArrayBuffer ? event.data : await event.data.arrayBuffer()
      await writer.write(data)
    }

    ws.addEventListener('message', handleMessage)
    ws.addEventListener('close', async () => {
      await socket.close()
    })
    ws.addEventListener('error', async () => {
      await socket.close()
    })

    const reader = socket.readable.getReader()
    const { done, value } = await reader.read()
    if (done) {
      throw Error('connection was done')
    }
    reader.releaseLock()
    ws.send(
      await new Blob([Protocol.RESPONSE_DATA(header.version), value]).arrayBuffer(),
    )

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
    return
  } catch (err) {
    console.error('UDP DNS failed, switching to DoH:', err)
  }

  // DoH fallback (application/dns-message wire format)
  async function dohQuery(raw: ArrayBuffer): Promise<ArrayBuffer> {
    const resp = await fetch('https://cloudflare-dns.com/dns-query', {
      method: 'POST',
      headers: {
        'Accept': 'application/dns-message',
        'Content-Type': 'application/dns-message',
      },
      body: raw,
    })
    if (!resp.ok) {
      throw new Error(`DoH failed with status ${resp.status}`)
    }
    return await resp.arrayBuffer()
  }

  const sendArrayBuffer = async (buf: ArrayBuffer) => {
    ws.send(await new Blob([buf]).arrayBuffer())
  }

  // Send initial response
  try {
    const initial = await dohQuery(header.rawData)
    ws.send(
      await new Blob([Protocol.RESPONSE_DATA(header.version), initial]).arrayBuffer(),
    )
  } catch (err) {
    console.error('DoH initial query failed:', err)
    safeCloseWebSocket(ws)
    return
  }

  ws.addEventListener('message', async (event) => {
    try {
      const data = event.data instanceof ArrayBuffer ? event.data : await event.data.arrayBuffer()
      const resp = await dohQuery(data)
      // For subsequent responses send raw DNS message (no protocol prefix)
      await sendArrayBuffer(resp)
    } catch (err) {
      console.error('DoH query error:', err)
      safeCloseWebSocket(ws)
    }
  })

  ws.addEventListener('close', () => {})
  ws.addEventListener('error', () => {})
}
