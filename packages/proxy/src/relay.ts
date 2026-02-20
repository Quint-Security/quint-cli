import { spawn, type ChildProcess } from "node:child_process";
import { createInterface } from "node:readline";
import { EventEmitter } from "node:events";

export interface RelayEvents {
  /** Fired for every line received on stdin (from parent / AI agent) */
  parentMessage: (line: string) => void;
  /** Fired for every line the child process writes to stdout */
  childMessage: (line: string) => void;
  /** Child process exited */
  childExit: (code: number | null, signal: string | null) => void;
  /** Unrecoverable error */
  error: (err: Error) => void;
}

/**
 * Relay manages:
 *  - Spawning the real MCP server as a child process
 *  - Reading JSON-RPC lines from stdin and forwarding to child stdin
 *  - Reading JSON-RPC lines from child stdout and forwarding to parent stdout
 *
 * The interceptor hooks into parentMessage/childMessage events to inspect,
 * allow, deny, or modify messages before they are forwarded.
 */
export class Relay extends EventEmitter {
  private child: ChildProcess | null = null;
  private command: string;
  private args: string[];

  constructor(command: string, args: string[]) {
    super();
    this.command = command;
    this.args = args;
  }

  start(): void {
    // Spawn the real MCP server
    this.child = spawn(this.command, this.args, {
      stdio: ["pipe", "pipe", "pipe"],
      env: process.env,
    });

    // Forward child stderr to our stderr (pass through diagnostics)
    this.child.stderr?.pipe(process.stderr);

    this.child.on("error", (err) => {
      this.emit("error", err);
    });

    this.child.on("exit", (code, signal) => {
      this.emit("childExit", code, signal);
    });

    // Read lines from child stdout
    if (this.child.stdout) {
      const childRl = createInterface({ input: this.child.stdout });
      childRl.on("line", (line) => {
        this.emit("childMessage", line);
      });
    }

    // Read lines from parent stdin
    const parentRl = createInterface({ input: process.stdin });
    parentRl.on("line", (line) => {
      this.emit("parentMessage", line);
    });

    parentRl.on("close", () => {
      // Parent closed stdin — close child's stdin so it can finish and exit
      this.child?.stdin?.end();
    });
  }

  /** Send a line to the child process's stdin */
  sendToChild(line: string): void {
    if (this.child?.stdin?.writable) {
      this.child.stdin.write(line + "\n");
    }
  }

  /** Send a line to the parent process's stdout */
  sendToParent(line: string): void {
    process.stdout.write(line + "\n");
  }

  /** Gracefully shut down the child */
  stop(): void {
    this.child?.kill();
  }
}
