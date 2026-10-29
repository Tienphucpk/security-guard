/**
 * Server-Sent Events (SSE) Stream Service for Real-time Security Alerts.
 * Manages active SSE clients, sends heartbeats, and broadcasts alert events.
 */

class AlertStreamService {
  constructor() {
    this.clients = new Set();
  }

  /**
   * Registers a new SSE client connection
   * @param {import('express').Request} req 
   * @param {import('express').Response} res 
   */
  addClient(req, res) {
    // Set SSE headers
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no',
      'Access-Control-Allow-Origin': '*'
    });

    if (typeof res.flushHeaders === 'function') {
      res.flushHeaders();
    }

    this.clients.add(res);

    // Initial connection acknowledgment
    const connectData = JSON.stringify({
      status: 'connected',
      message: 'Connected to Security Guard Real-time Alert Stream',
      timestamp: new Date().toISOString()
    });
    res.write(`event: connected\ndata: ${connectData}\n\n`);

    // Periodic heartbeat comment to keep the connection alive through proxies
    const heartbeatTimer = setInterval(() => {
      try {
        res.write(': heartbeat\n\n');
      } catch (err) {
        clearInterval(heartbeatTimer);
        this.clients.delete(res);
      }
    }, 20000);

    // Handle connection closure
    req.on('close', () => {
      clearInterval(heartbeatTimer);
      this.clients.delete(res);
    });

    req.on('error', () => {
      clearInterval(heartbeatTimer);
      this.clients.delete(res);
    });
  }

  /**
   * Broadcasts an event to all connected SSE clients
   * @param {string} eventType 
   * @param {Object} data 
   */
  broadcast(eventType, data) {
    if (this.clients.size === 0) return;

    const payload = `event: ${eventType}\ndata: ${JSON.stringify(data)}\n\n`;

    for (const client of this.clients) {
      try {
        client.write(payload);
      } catch (err) {
        this.clients.delete(client);
      }
    }
  }

  /**
   * Returns current active client count
   * @returns {number}
   */
  getClientCount() {
    return this.clients.size;
  }
}

module.exports = new AlertStreamService();
