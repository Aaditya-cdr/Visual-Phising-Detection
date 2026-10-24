/**
 * Minimal PNG generator for Chrome Extension icons
 * Generates valid PNG images with a cyan security shield on dark blue background.
 */

import fs from 'fs';
import path from 'path';
import zlib from 'zlib';

function createShieldPng(size) {
  // Width, height, 4 channels (RGBA)
  const width = size;
  const height = size;
  const rawData = Buffer.alloc(height * (width * 4 + 1));

  let offset = 0;
  for (let y = 0; y < height; y++) {
    rawData[offset++] = 0; // Filter byte: None

    for (let x = 0; x < width; x++) {
      // Coordinate normalized -1 to 1
      const nx = (x / width) * 2 - 1;
      const ny = (y / height) * 2 - 1;

      // Shield shape condition: y > -0.7 and |x| < (0.8 - (ny + 0.7)*0.4) for top part,
      // and tapering to bottom point
      const isInsideShield = 
        ny >= -0.7 && ny <= 0.8 &&
        Math.abs(nx) <= (0.75 - Math.max(0, ny) * 0.7);

      if (isInsideShield) {
        // Cyan shield color #38bdf8
        rawData[offset++] = 0x38; // R
        rawData[offset++] = 0xbd; // G
        rawData[offset++] = 0xf8; // B
        rawData[offset++] = 0xff; // A
      } else {
        // Dark background #0b0f19
        rawData[offset++] = 0x0b;
        rawData[offset++] = 0x0f;
        rawData[offset++] = 0x19;
        rawData[offset++] = 0xff;
      }
    }
  }

  const compressed = zlib.deflateSync(rawData);

  // Build PNG chunks
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

  // IHDR Chunk
  const ihdrData = Buffer.alloc(13);
  ihdrData.writeUInt32BE(width, 0);
  ihdrData.writeUInt32BE(height, 4);
  ihdrData[8] = 8; // bit depth
  ihdrData[9] = 6; // color type RGBA
  ihdrData[10] = 0; // compression
  ihdrData[11] = 0; // filter
  ihdrData[12] = 0; // interlace

  const ihdrChunk = createChunk('IHDR', ihdrData);
  const idatChunk = createChunk('IDAT', compressed);
  const iendChunk = createChunk('IEND', Buffer.alloc(0));

  return Buffer.concat([signature, ihdrChunk, idatChunk, iendChunk]);
}

function createChunk(type, data) {
  const len = data.length;
  const chunk = Buffer.alloc(len + 12);
  chunk.writeUInt32BE(len, 0);
  chunk.write(type, 4, 4, 'ascii');
  data.copy(chunk, 8);

  const crc = crc32(chunk.subarray(4, len + 8));
  chunk.writeUInt32BE(crc >>> 0, len + 8);
  return chunk;
}

// CRC32 table & function
const crcTable = [];
for (let n = 0; n < 256; n++) {
  let c = n;
  for (let k = 0; k < 8; k++) {
    if (c & 1) c = 0xedb88320 ^ (c >>> 1);
    else c = c >>> 1;
  }
  crcTable[n] = c;
}

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c = crcTable[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  }
  return c ^ 0xffffffff;
}

const dir = path.resolve('extension/icons');
fs.mkdirSync(dir, { recursive: true });

fs.writeFileSync(path.join(dir, 'icon-16.png'), createShieldPng(16));
fs.writeFileSync(path.join(dir, 'icon-48.png'), createShieldPng(48));
fs.writeFileSync(path.join(dir, 'icon-128.png'), createShieldPng(128));
console.log('Successfully generated extension icons: 16px, 48px, 128px.');
