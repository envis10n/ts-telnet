import net from "net";
import tls from "tls";
import { EventEmitter as EE } from "events";
import { uint8 } from "./buf_util";

type Option<T> = T | null;

enum NVT {
    NUL = 0,
    LF = 10,
    CR = 13,
    BEL = 7,
    BS = 8,
    HT = 9,
    VT = 11,
    FF = 12
}

enum Commands {
    SE = 240,
    NOP = 241,
    DM = 242,
    BRK = 243,
    IP = 244,
    AO = 245,
    AYT = 246,
    EC = 247,
    EL = 248,
    GA = 249,
    SB = 250,
    WILL = 251,
    WONT = 252,
    DO = 253,
    DONT = 254,
    IAC = 255
}

enum Options {
    TB = 0,
    ECHO = 1,
    SGA = 3,
    STATUS = 5,
    TM = 6,
    TT = 24,
    WS = 31,
    TS = 32,
    RFC = 33,
    LM = 34,
    EV = 36,
    SLE = 45,
    ATCP = 201
}

interface IACResult {
    iac: Buffer[];
    chunk: Buffer;
}

function findIAC(chunk: Buffer): IACResult {
    const res: Buffer[] = [];
    let i = chunk.findIndex((v) => v === Commands.IAC);
    while (i !== -1) {
        const iv = chunk.findIndex((v) => v === Commands.SE);
        if (iv !== -1 && chunk[i + 1] === Commands.SB) {
            const b = Buffer.alloc(iv + 1 - i);
            chunk.copy(b, 0, i, iv + 1);
            const c1 = chunk.subarray(0, i);
            const c2 = chunk.subarray(iv + 1);
            chunk = Buffer.concat([c1, c2]);
            res.push(b);
        } else {
            const b = Buffer.alloc(3);
            chunk.copy(b, 0, i, i + 3);
            const c1 = chunk.subarray(0, i);
            const c2 = chunk.subarray(i + 3);
            chunk = Buffer.concat([c1, c2]);
            res.push(b);
        }
        i = chunk.findIndex((v) => v === Commands.IAC);
    }
    return {
        iac: res,
        chunk,
    };
}

function findLF(chunk: Buffer) {
    const f = chunk.toString().split("\n").filter((v) => v !== "");
    return f.map((v) => Buffer.from(v));
}

namespace Telnet {
    export class Client extends EE {
        private buffer: Buffer = Buffer.alloc(0);
        private callback: Option<(data: Buffer) => void> = null;
        private prompt: string = "> ";
        public atcp: boolean = false;
        constructor(private socket: net.Socket, public defaultPrompt: string = "> ") {
            super();
            this.prompt = this.defaultPrompt;
            socket.on("data", (chunk) => {
                this.emit("chunk", chunk);
                this.buffer = Buffer.concat([this.buffer, chunk]);
                const fiac = findIAC(this.buffer);
                this.buffer = fiac.chunk;
                for (const iac of fiac.iac) {
                    chunk = fiac.chunk;
                    this.emit("iac", iac);
                    if (iac[1] === Commands.WILL) {
                        this.emit("will", iac[2]);
                    } else if (iac[1] === Commands.WONT) {
                        this.emit("wont", iac[2]);
                    } else if (iac[1] === Commands.DO) {
                        this.emit("do", iac[2]);
                    } else if (iac[1] === Commands.DONT) {
                        this.emit("dont", iac[2]);
                    } else if (iac[1] === Commands.SB) {
                        this.emit("sb", iac[2], iac[3], iac.subarray(3, iac.length - 2));
                    }
                }
                const bufs = findLF(this.buffer);
                if (bufs.length >= 2) {
                    this.buffer = bufs[bufs.length - 1];
                    bufs.splice(bufs.length - 1, 1);
                    for (let i = 0; i < bufs.length; i++) {
                        if (i === 0 && this.callback !== null) {
                            this.callback(bufs[i]);
                        } else {
                            this.emit("data", bufs[i]);
                        }
                    }
                } else if (this.buffer.toString().substring(this.buffer.length - 1) === "\n") {
                    if (this.callback !== null) {
                        this.callback(this.buffer.subarray(0, this.buffer.length - 1));
                    } else {
                        this.emit("data", this.buffer.subarray(0, this.buffer.length - 1));
                    }
                    this.buffer = Buffer.alloc(0);
                }
            });
            socket.on("error", (err) => {
                this.emit("error", err);
            });
            socket.on("end", () => {
                this.emit("end");
            });
            socket.on("close", (had_error) => {
                this.emit("close", had_error);
            });
            this.on("will", (opt) => {
                if (opt === Options.ATCP) {
                    this.atcp = true;
                    this.do(Options.ATCP);
                }
            });
            this.on("wont", (opt) => {
                if (opt === Options.ATCP) {
                    this.atcp = false;
                }
            });
            this.on("sb", (opt, val, data: Buffer) => {
                if (opt === Options.ATCP) {
                    const d = data.toString().split(" ");
                    const call: string = d[0];
                    const json: string = d.slice(1).join(" ");
                    let jobj: Object | undefined;
                    if (json !== "") {
                        try {
                            jobj = JSON.parse(json);
                        } catch (e) {
                            jobj = undefined;
                        }
                    }
                    this.emit("gmcp", call, jobj);
                    const command = call.split(".");
                    if (command[0] === "Core") {
                        switch (command[1]) {
                            case "Supports":
                                if (command[2] === "Set") {
                                    // Support array
                                    const ar = jobj as string[];
                                    const ar2 = ar.map((v) => {
                                        const dar = v.split(" ");
                                        return {
                                            option: dar[0],
                                            support: Boolean(dar[1]),
                                        };
                                    });
                                    this.emit("Core.Supports.Set", ar2);
                                } else {
                                    this.emit(call, jobj);
                                }
                                break;
                            default:
                                this.emit(call, jobj);
                                break;
                        }
                    }
                }
            });
            this.will(Options.ATCP);
        }
        public ask(prompt: string, mask: boolean = false): Promise<string> {
            return new Promise((resolve, reject) => {
                this.callback = (data: Buffer) => {
                    this.callback = null;
                    this.prompt = this.defaultPrompt;
                    if (mask) {
                        this.wont(Options.ECHO);
                    }
                    resolve(data.toString());
                };
                this.prompt = prompt;
                if (mask) {
                    this.will(Options.ECHO);
                }
                this.write("\r\n" + this.prompt);
            });
        }
        public send(data: string) {
            this.socket.write(Buffer.from(data + "\n\r"));
        }
        public IAC(command: number, option: number) {
            this.socket.write(uint8(Commands.IAC, command, option));
        }
        public write(data: string | Buffer | Uint8Array) {
            this.socket.write(data);
        }
        public will(option: Options) {
            this.IAC(Commands.WILL, option);
        }
        public wont(option: Options) {
            this.IAC(Commands.WONT, option);
        }
        public do(option: Options) {
            this.IAC(Commands.DO, option);
        }
        public dont(option: Options) {
            this.IAC(Commands.DONT, option);
        }
        public end() {
            this.socket.end();
        }
    }

    export class Server extends EE {
        private clients: Client[] = [];
        private server: net.Server;
        constructor(public readonly host: string = "localhost", public readonly port: number = 23) {
            super();
            this.server = net.createServer();
            this.server.on("connection", (socket) => {
                let client: Client | null = new Client(socket);
                client.on("close", () => {
                    this.clients.splice(this.clients.findIndex((v) => v === client), 1);
                    client = null;
                });
                this.clients.push(client);
                this.emit("connection", client);
            });
            this.server.listen(port, host, () => {
                this.emit("listening");
            });
        }
    }
    export class SecureServer extends EE {
        private clients: Client[] = [];
        private server: tls.Server;
        constructor(public readonly host: string = "localhost", public readonly port: number = 24, context: {
            options: tls.SecureContextOptions,
            hostname: string;
        }) {
            super();
            this.server = tls.createServer();
            this.server.addContext(context.hostname, context.options);
            this.server.on("secureConnection", (socket) => {
                let client: Client | null = new Client(socket);
                client.on("close", () => {
                    this.clients.splice(this.clients.findIndex((v) => v === client), 1);
                    client = null;
                });
                this.clients.push(client);
                this.emit("connection", client);
            });
            this.server.listen(port, host, () => {
                this.emit("listening");
            });
        }
    }
}

export = Telnet;
