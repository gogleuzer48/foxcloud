import { processHeader } from '../protocols/index'
import { processTCP } from './tcp'
import { safeCloseWebSocket } from '../utils/helpers'
import { processDNS } from './dns'

import type { Env } from '../core/types'

/**
 * Decodes early data from base64url encoding
 * @param earlyData - Base64url encoded string
 * @returns Decoded ArrayBuffer
 */
function decodeEarlyData(earlyData: string): ArrayBuffer {
  earlyData = earlyData.replace(/-/g, '+').replace(/_/g, '/')
  const binaryStr = atob(earlyData)
  const buffer = new ArrayBuffer(binaryStr.length)
  const view = new Uint8Array(buffer)
  for (let i = 0; i < binaryStr.length; i++) {
    view[i] = binaryStr.charCodeAt(i)
  }
  return buffer
}

/**
 * Gets the initial header from WebSocket connection
 * @param ws - WebSocket connection
 * @param earlyData - Early data from Sec-WebSocket-Protocol header
 * @returns Promise resolving to ArrayBuffer of header data
 */
function getHeader(
  ws: WebSocket,
  earlyData: string | null,
): Promise<ArrayBuffer> {
  return new Promise((resolve, reject) => {
    if (earlyData) {
      try {
        const data = decodeEarlyData(earlyData)
        resolve(data)
      } catch (err) {
        reject(err)
      }
    }

    const handleMsg = (event: MessageEvent) => {
      if (typeof event.data === 'string') {
        reject('invalid data')
      } else {
        resolve(event.data)
      }
      ws.removeEventListener('message', handleMsg)
      ws.removeEventListener('error', handleErr)
    }

    const handleErr = (event: Event) => {
      // @ts-ignore
      reject(event.error || 'WebSocket error')
      ws.removeEventListener('message', handleMsg)
      ws.removeEventListener('error', handleErr)
    }

    ws.addEventListener('message', handleMsg)
    ws.addEventListener('error', handleErr)

    setTimeout(() => {
      reject('timeout')
      ws.removeEventListener('message', handleMsg)
      ws.removeEventListener('error', handleErr)
    }, 10000)
  })
}

/**
 * Processes incoming WebSocket connections
 * @param request - Incoming request
 * @param env - Environment variables
 * @returns Response with WebSocket upgrade
 */
export function processWebSocket(request: Request, env: Env): Response {
  const uuids = env.UUID.split(',').filter((v) => v !== '')
  // Parse PROXY_IP entries into structured objects supporting optional servername (format: host:port or host:port@servername)
  type ProxyEntry = { host: string; port: number; servername?: string }
  const proxyEntries: ProxyEntry[] = (env.PROXY_IP || '')
    .split(',')
    .map((s) => s.trim())
    .filter((v) => v !== '')
    .map((v) => {
      // support optional servername after @
      let servername: string | undefined
      const atIndex = v.indexOf('@')
      if (atIndex !== -1) {
        servername = v.slice(atIndex + 1)
        v = v.slice(0, atIndex)
      }

      // handle IPv6: [addr]:port
      let host = ''
      let portStr = ''
      if (v.startsWith('[')) {
        const closeIdx = v.indexOf(']')
        host = v.slice(1, closeIdx)
        portStr = v.slice(closeIdx + 2)
      } else {
        const lastColon = v.lastIndexOf(':')
        host = v.slice(0, lastColon)
        portStr = v.slice(lastColon + 1)
      }

      const port = Number(portStr) || 443
      return { host, port, servername }
    })
    .filter((p) => {
      if (!p.host || !Number.isFinite(p.port) || p.port <= 0) {
        console.error(`Invalid PROXY_IP entry ignored: "${JSON.stringify(p)}"`)
        return false
      }
      return true
    })

  // Log parsed proxy entries for debugging
  if (proxyEntries.length === 0) {
    console.warn('No valid PROXY_IP entries found; direct connections only')
  } else {
    console.info(`PROXY_IP parsed: ${JSON.stringify(proxyEntries)}`)
  }

  const [client, server] = Object.values(new WebSocketPair())
  if (server === undefined) {
    throw 'WebSocket server not defined'
  }
  if (client === undefined) {
    throw 'WebSocket client not defined'
  }

  server.accept()

  getHeader(server, request.headers.get('Sec-WebSocket-Protocol'))
    .then((v) => processHeader(v, uuids))
    .then(async (header) => {
      if (header.isUDP) {
        if (header.port === 53) {
          await processDNS(server, header)
        } else {
          throw Error('UDP transport is unsupported')
        }
      }

      await processTCP(server, header, proxyEntries)
    })
    .catch((err) => {
      console.error(err)
      safeCloseWebSocket(server)
    })

  return new Response(null, {
    status: 101,
    webSocket: client,
  })
}