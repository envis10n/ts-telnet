export function uint8(...args: number[]): Buffer {
    const b = Buffer.alloc(args.length);
    for (let i = 0; i < args.length; i++) {
        b.writeUInt8(args[i], i);
    }
    return b;
}