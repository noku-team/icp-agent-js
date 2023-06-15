/* eslint-disable @typescript-eslint/ban-ts-comment */
// Package adapted from https://www.npmjs.com/package/hdkey
/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-this-alias */
import assert from 'assert';
import { Buffer } from 'buffer';
import bs58check from 'bs58check';
import secp256k1 from 'secp256k1';
import CryptoJS from 'crypto-js';
import { createHash } from 'crypto'


const MASTER_SECRET = Buffer.from('Bitcoin seed', 'utf8');
const HARDENED_OFFSET = 0x80000000;
const LEN = 78;

// Bitcoin hardcoded by default, can use package `coininfo` for others
const BITCOIN_VERSIONS = { private: 0x0488ade4, public: 0x0488b21e };


function convertWordArrayToUint8Array(wordArray: CryptoJS.lib.WordArray) {
	// eslint-disable-next-line prefer-const
	let len = wordArray.words.length,
		// eslint-disable-next-line prefer-const
		u8_array = new Uint8Array(len << 2),
		offset = 0, word, i
	;
	for (i=0; i<len; i++) {
		word = wordArray.words[i];
		u8_array[offset++] = word >> 24;
		u8_array[offset++] = (word >> 16) & 0xff;
		u8_array[offset++] = (word >> 8) & 0xff;
		u8_array[offset++] = word & 0xff;
	}
	return u8_array;
}

// function convertUint8ArrayToWordArray(u8Array: Uint8Array) {
// 	// eslint-disable-next-line prefer-const
// 	let words = [], i = 0, len = u8Array.length;

// 	while (i < len) {
// 		words.push(
// 			(u8Array[i++] << 24) |
// 			(u8Array[i++] << 16) |
// 			(u8Array[i++] << 8)  |
// 			(u8Array[i++])
// 		);
// 	}

// 	return {
// 		sigBytes: words.length * 4,
// 		words: words
// 	};
// }

// function convertWordArrayToUint8Array(wordArray: CryptoJS.lib.WordArray) {
//   const l = wordArray.sigBytes;
//   const words = wordArray.words;
//   const result = new Uint8Array(l);
//   let i=0 /*dst*/, j=0 /*src*/;
//   // eslint-disable-next-line no-constant-condition
//   while(true) {
//       // here i is a multiple of 4
//       if (i==l)
//           break;
//       const w = words[j++];
//       result[i++] = (w & 0xff000000) >>> 24;
//       if (i==l)
//           break;
//       result[i++] = (w & 0x00ff0000) >>> 16;
//       if (i==l)
//           break;
//       result[i++] = (w & 0x0000ff00) >>> 8;
//       if (i==l)
//           break;
//       result[i++] = (w & 0x000000ff);
//   }
//   return result;
// }

/**
 *
 * @param versions any
 */
function HDKey(versions?: any) {
  // @ts-ignore
  this.versions = versions || BITCOIN_VERSIONS;
  // @ts-ignore
  this.depth = 0;
  // @ts-ignore
  this.index = 0;
  // @ts-ignore
  this._privateKey = null;
  // @ts-ignore
  this._publicKey = null;
  // @ts-ignore
  this.chainCode = null;
  // @ts-ignore
  this._fingerprint = 0;
  // @ts-ignore
  this.parentFingerprint = 0;
}

Object.defineProperty(HDKey.prototype, 'fingerprint', {
  get: function () {
    return this._fingerprint;
  },
});
Object.defineProperty(HDKey.prototype, 'identifier', {
  get: function () {
    return this._identifier;
  },
});
Object.defineProperty(HDKey.prototype, 'pubKeyHash', {
  get: function () {
    return this.identifier;
  },
});

Object.defineProperty(HDKey.prototype, 'privateKey', {
  get: function () {
    return this._privateKey;
  },
  set: function (value) {
    assert.equal(value.length, 32, 'Private key must be 32 bytes.');
    assert(secp256k1.privateKeyVerify(value) === true, 'Invalid private key');

    this._privateKey = value;
    this._publicKey = Buffer.from(secp256k1.publicKeyCreate(value, true));
    this._identifier = hash160(this.publicKey);
    this._fingerprint = this._identifier.slice(0, 4).readUInt32BE(0);
  },
});

Object.defineProperty(HDKey.prototype, 'publicKey', {
  get: function () {
    return this._publicKey;
  },
  set: function (value) {
    assert(value.length === 33 || value.length === 65, 'Public key must be 33 or 65 bytes.');
    assert(secp256k1.publicKeyVerify(value) === true, 'Invalid public key');

    this._publicKey = Buffer.from(secp256k1.publicKeyConvert(value, true)); // force compressed point
    this._identifier = hash160(this.publicKey);
    this._fingerprint = this._identifier.slice(0, 4).readUInt32BE(0);
    this._privateKey = null;
  },
});

Object.defineProperty(HDKey.prototype, 'privateExtendedKey', {
  get: function () {
    if (this._privateKey)
      return bs58check.encode(
        serialize(
          this,
          this.versions.private,
          Buffer.concat([Buffer.alloc(1, 0), this.privateKey]),
        ),
      );
    else return null;
  },
});

Object.defineProperty(HDKey.prototype, 'publicExtendedKey', {
  get: function () {
    return bs58check.encode(serialize(this, this.versions.public, this.publicKey));
  },
});

HDKey.prototype.derive = function (path: string) {
  if (path === 'm' || path === 'M' || path === "m'" || path === "M'") {
    return this;
  }

  const entries = path.split('/');
  let hdkey = this;
  entries.forEach(function (c, i) {
    if (i === 0) {
      assert(/^[mM]{1}/.test(c), 'Path must start with "m" or "M"');
      return;
    }

    const hardened = c.length > 1 && c[c.length - 1] === "'";
    let childIndex = parseInt(c, 10); // & (HARDENED_OFFSET - 1)
    assert(childIndex < HARDENED_OFFSET, 'Invalid index');
    if (hardened) childIndex += HARDENED_OFFSET;

    hdkey = hdkey.deriveChild(childIndex);
  });

  return hdkey;
};

HDKey.prototype.deriveChild = function (index: number) {
  const isHardened = index >= HARDENED_OFFSET;
  const indexBuffer = Buffer.allocUnsafe(4);
  indexBuffer.writeUInt32BE(index, 0);

  let data;

  if (isHardened) {
    // Hardened child
    assert(this.privateKey, 'Could not derive hardened child key');

    let pk = this.privateKey;
    const zb = Buffer.alloc(1, 0);
    pk = Buffer.concat([zb, pk]);

    // data = 0x00 || ser256(kpar) || ser32(index)
    data = Buffer.concat([pk, indexBuffer]);
  } else {
    // Normal child
    // data = serP(point(kpar)) || ser32(index)
    //      = serP(Kpar) || ser32(index)
    data = Buffer.concat([this.publicKey, indexBuffer]);
  }

  // const I2 = createHmac('sha512', this.chainCode).update(data).digest();

  console.log(this.chainCode)

  const I = Buffer.from(convertWordArrayToUint8Array(CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA512, this.chainCode.toString()).update(data.toString('hex')).finalize()));
  const IL = I.slice(0, 32);
  const IR = I.slice(32);

  const hd = new (HDKey as any)(this.versions);

  // Private parent key -> private child key
  if (this.privateKey) {
    // ki = parse256(IL) + kpar (mod n)
    try {
      hd.privateKey = Buffer.from(secp256k1.privateKeyTweakAdd(Buffer.from(this.privateKey), IL));
      // throw if IL >= n || (privateKey + IL) === 0
    } catch (err) {
      // In case parse256(IL) >= n or ki == 0, one should proceed with the next value for i
      return this.deriveChild(index + 1);
    }
    // Public parent key -> public child key
  } else {
    // Ki = point(parse256(IL)) + Kpar
    //    = G*IL + Kpar
    try {
      hd.publicKey = Buffer.from(
        secp256k1.publicKeyTweakAdd(Buffer.from(this.publicKey), IL, true),
      );
      // throw if IL >= n || (g**IL + publicKey) is infinity
    } catch (err) {
      // In case parse256(IL) >= n or Ki is the point at infinity, one should proceed with the next value for i
      return this.deriveChild(index + 1);
    }
  }

  hd.chainCode = IR;
  hd.depth = this.depth + 1;
  hd.parentFingerprint = this.fingerprint; // .readUInt32BE(0)
  hd.index = index;

  return hd;
};

HDKey.prototype.sign = function (hash: Buffer) {
  return Buffer.from(secp256k1.ecdsaSign(hash, this.privateKey).signature);
};

HDKey.prototype.verify = function (hash: Buffer, signature: Buffer) {
  return secp256k1.ecdsaVerify(
    Uint8Array.from(signature),
    Uint8Array.from(hash),
    Uint8Array.from(this.publicKey),
  );
};

HDKey.prototype.wipePrivateData = function () {
  // if (this._privateKey) randomBytes(this._privateKey.length).copy(this._privateKey);
  if (this._privateKey) this._privateKey = CryptoJS.lib.WordArray.random(this._privateKey.length);
  this._privateKey = null;
  return this;
};

HDKey.prototype.toJSON = function () {
  return {
    xpriv: this.privateExtendedKey,
    xpub: this.publicExtendedKey,
  };
};

HDKey.fromMasterSeed = function (seedBuffer: Buffer, versions?: any) {
  // const I = createHmac('sha512', MASTER_SECRET).update(seedBuffer).digest();
  const I = Buffer.from(convertWordArrayToUint8Array(CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA512, MASTER_SECRET.toString()).update(seedBuffer.toString()).finalize()));
  const IL = I.slice(0, 32);
  const IR = I.slice(32);

  const hdkey = new (HDKey as any)(versions);
  hdkey.chainCode = IR;
  hdkey.privateKey = IL;

  return hdkey;
};

HDKey.fromExtendedKey = function (base58key: string, versions?: any) {
  // => version(4) || depth(1) || fingerprint(4) || index(4) || chain(32) || key(33)
  versions = versions || BITCOIN_VERSIONS;
  const hdkey = new (HDKey as any)(versions);

  const keyBuffer = bs58check.decode(base58key);

  const version = keyBuffer.readUInt32BE(0);
  assert(
    version === versions.private || version === versions.public,
    'Version mismatch: does not match private or public',
  );

  hdkey.depth = keyBuffer.readUInt8(4);
  hdkey.parentFingerprint = keyBuffer.readUInt32BE(5);
  hdkey.index = keyBuffer.readUInt32BE(9);
  hdkey.chainCode = keyBuffer.slice(13, 45);

  const key = keyBuffer.slice(45);
  if (key.readUInt8(0) === 0) {
    // private
    assert(version === versions.private, 'Version mismatch: version does not match private');
    hdkey.privateKey = key.slice(1); // cut off first 0x0 byte
  } else {
    assert(version === versions.public, 'Version mismatch: version does not match public');
    hdkey.publicKey = key;
  }

  return hdkey;
};

HDKey.fromJSON = function (obj: any) {
  return HDKey.fromExtendedKey(obj.xpriv);
};

function serialize(hdkey: any, version: any, key: any) {
  // => version(4) || depth(1) || fingerprint(4) || index(4) || chain(32) || key(33)
  const buffer = Buffer.allocUnsafe(LEN);

  buffer.writeUInt32BE(version, 0);
  buffer.writeUInt8(hdkey.depth, 4);

  const fingerprint = hdkey.depth ? hdkey.parentFingerprint : 0x00000000;
  buffer.writeUInt32BE(fingerprint, 5);
  buffer.writeUInt32BE(hdkey.index, 9);

  hdkey.chainCode.copy(buffer, 13);
  key.copy(buffer, 45);

  return buffer;
}

function hash160(buf: Buffer) {
  // const sha = createHash('sha256').update(buf).digest();
  const sha = CryptoJS.algo.SHA256.create().update(buf.toString()).finalize();
  // return createHash('ripemd160').update(sha).digest();
  return Buffer.from(convertWordArrayToUint8Array(CryptoJS.algo.RIPEMD160.create().update(sha).finalize()));
}

HDKey.HARDENED_OFFSET = HARDENED_OFFSET;
export default HDKey;
