import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

// Remembering every port ever handed out eventually covers enough of the ephemeral range that the
// kernel, which hands them out in order, can only offer ports already in the set. A window of recent
// ones is what the guarantee actually needs: a port handed out this long ago is either bound or gone.
const RECENT_PORTS = 256;
const handedOut = new Set<number>();

function rememberPort(port: number): void {
  handedOut.add(port);
  if (handedOut.size > RECENT_PORTS) {
    handedOut.delete(handedOut.values().next().value as number);
  }
}

function bindEphemeral(): Promise<{ server: Server; port: number }> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.listen(0, () => resolve({ server, port: (server.address() as AddressInfo).port }));
    server.on("error", reject);
  });
}

const REROLLS = 10;

/**
 * Ports for a process that binds its own sockets, so they are released before it can take them.
 * Anything served in-process should bind and hold instead, which cannot lose the port to whatever
 * binds next.
 *
 * The ports are held open all at once and only released together, so no two of them can be equal,
 * and `handedOut` keeps that guarantee across calls: a bind landing on a port already given away
 * stays open while it re-rolls, so the OS cannot offer it again. What survives is a race with a
 * process outside this one, which the caller has to retry.
 */
export async function allocatePorts(count: number): Promise<number[]> {
  const held: Server[] = [];
  const ports: number[] = [];

  try {
    while (ports.length < count) {
      let port = 0;
      for (let attempt = 0; attempt < REROLLS; attempt++) {
        const bound = await bindEphemeral();
        held.push(bound.server);
        port = bound.port;
        if (!handedOut.has(port)) {
          break;
        }
      }
      // A range too crowded to re-roll out of takes the repeat rather than failing: the ports of
      // this call are still distinct from each other, and the caller's retry covers the rest.
      rememberPort(port);
      ports.push(port);
    }
  } finally {
    await Promise.all(held.map((server) => new Promise((resolve) => server.close(resolve))));
  }

  return ports;
}
