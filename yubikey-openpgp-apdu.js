/**
 * yubikey-openpgp-apdu.js
 *
 * Low-level APDU layer for the OpenPGP Smart Card Application on YubiKey.
 * Implements ISO/IEC 7816-4 command APDUs over WebUSB.
 *
 * Spec: OpenPGP Smart Card Application v3.4.1
 * https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf
 *
 * Usage:
 *   const yk = new YubiKeyOpenPGP();
 *   await yk.connect();
 *   await yk.selectOpenPGPApplet();
 *   const pubkey = await yk.getPublicKey(YubiKeyOpenPGP.KEY_SLOT.SIGN);
 *   await yk.disconnect();
 */

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Yubico USB vendor ID */
const YUBICO_VENDOR_ID = 0x1050;

/**
 * OpenPGP applet AID (Application Identifier).
 * D2 76 00 01 24 01  — registered OpenPGP AID
 */
const OPENPGP_AID = new Uint8Array([0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]);

/**
 * Key slot control-reference templates (CRT).
 * Used in PSO commands and key import.
 */
const KEY_SLOT = {
  SIGN:    0xB6,   // Signature key
  DECRYPT: 0xB8,   // Confidentiality / decryption key
  AUTH:    0xA4,   // Authentication key
};

/**
 * Data Object (DO) tags for key fingerprints, public keys, etc.
 * Ref: OpenPGP card spec §4.4
 */
const DO_TAG = {
  CARDHOLDER_RELATED:  0x65,
  APP_RELATED:         0x6E,
  SECURITY_SUPPORT:    0x93,
  PRIVATE_USE_1:       0x0101,
  PRIVATE_USE_2:       0x0102,
  SIGN_COUNT:          0x0093,
  FINGERPRINTS:        0x00C5,   // All three fingerprints, 60 bytes
  SIGN_FP:             0x00C7,
  DECRYPT_FP:          0x00C8,
  AUTH_FP:             0x00C9,
  CA_FP_1:             0x00CA,
  CA_FP_2:             0x00CB,
  CA_FP_3:             0x00CC,
  KEY_INFO:            0x00DE,
  ALGORITHM_ATTRS_SIGN:    0x00C1,
  ALGORITHM_ATTRS_DECRYPT: 0x00C2,
  ALGORITHM_ATTRS_AUTH:    0x00C3,
  PW_STATUS:           0x00C4,
  CARDHOLDER_NAME:     0x005B,
  LANGUAGE_PREFS:      0x5F2D,
  SEX:                 0x5F35,
  URL:                 0x5F50,
  HISTORICAL_BYTES:    0x5F52,
  CARDHOLDER_CERT:     0x7F21,
  PW1_BLOCK:           0x0081,  // PIN block for PW1 (user PIN, signing)
  PW3_BLOCK:           0x0083,  // PIN block for PW3 (admin PIN)
};

/** Status words (SW1 SW2) */
const SW = {
  SUCCESS:              0x9000,
  MORE_DATA:            0x6100,   // SW2 = remaining bytes
  WRONG_LENGTH:         0x6700,
  SECURITY_NOT_SATISFIED: 0x6982,
  AUTH_BLOCKED:         0x6983,
  WRONG_DATA:           0x6984,
  CONDITIONS_NOT_SATISFIED: 0x6985,
  WRONG_PARAMETERS:     0x6B00,
  INS_NOT_SUPPORTED:    0x6D00,
  CLA_NOT_SUPPORTED:    0x6E00,
  NOT_FOUND:            0x6A82,
  INCORRECT_PIN:        0x63C0,   // SW2 low nibble = remaining tries
};

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

/** Convert a hex string "A1 B2 C3" or "A1B2C3" → Uint8Array */
function hexToBytes(hex) {
  const clean = hex.replace(/\s+/g, '');
  const arr = new Uint8Array(clean.length / 2);
  for (let i = 0; i < arr.length; i++) {
    arr[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return arr;
}

/** Convert Uint8Array → hex string with spaces */
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
}

/** Concatenate multiple Uint8Arrays */
function concatBytes(...arrays) {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) { out.set(a, offset); offset += a.length; }
  return out;
}

/** Encode a length in BER-TLV form */
function berLength(len) {
  if (len < 0x80) return new Uint8Array([len]);
  if (len < 0x100) return new Uint8Array([0x81, len]);
  return new Uint8Array([0x82, (len >> 8) & 0xFF, len & 0xFF]);
}

/** Build a simple BER-TLV TLV triplet */
function tlv(tag, value) {
  const tagBytes = tag > 0xFF
    ? new Uint8Array([(tag >> 8) & 0xFF, tag & 0xFF])
    : new Uint8Array([tag & 0xFF]);
  return concatBytes(tagBytes, berLength(value.length), value);
}

/**
 * Parse a flat sequence of BER-TLV objects.
 * Returns Map<tag (number), Uint8Array value>
 */
function parseTLV(data) {
  const map = new Map();
  let i = 0;
  while (i < data.length) {
    // Tag
    let tag = data[i++];
    if ((tag & 0x1F) === 0x1F) { tag = (tag << 8) | data[i++]; } // two-byte tag
    if (i >= data.length) break;
    // Length
    let len;
    if (data[i] < 0x80) {
      len = data[i++];
    } else if (data[i] === 0x81) {
      len = data[++i]; i++;
    } else if (data[i] === 0x82) {
      len = (data[i + 1] << 8) | data[i + 2]; i += 3;
    } else {
      break; // unsupported length encoding
    }
    map.set(tag, data.slice(i, i + len));
    i += len;
  }
  return map;
}

// ---------------------------------------------------------------------------
// APDU builder
// ---------------------------------------------------------------------------

/**
 * Build a command APDU buffer.
 *
 * @param {number} cla   - Class byte
 * @param {number} ins   - Instruction byte
 * @param {number} p1    - Parameter 1
 * @param {number} p2    - Parameter 2
 * @param {Uint8Array|null} data - Command data (Lc field)
 * @param {boolean} expectResponse - Whether to append Le=0x00
 */
function buildAPDU(cla, ins, p1, p2, data = null, expectResponse = true) {
  const parts = [new Uint8Array([cla, ins, p1, p2])];
  if (data && data.length > 0) {
    if (data.length > 255) {
      // Extended length APDU (3-byte Lc)
      parts.push(new Uint8Array([0x00, (data.length >> 8) & 0xFF, data.length & 0xFF]));
    } else {
      parts.push(new Uint8Array([data.length]));
    }
    parts.push(data);
  }
  if (expectResponse) {
    parts.push(new Uint8Array([0x00])); // Le = 0 means "return all available"
  }
  return concatBytes(...parts);
}

// ---------------------------------------------------------------------------
// USB transport
// ---------------------------------------------------------------------------

/**
 * Low-level USB framing for YubiKey CCID interface.
 *
 * YubiKey exposes a CCID (USB Smart Card) interface.
 * CCID bulk-out packets have a 10-byte header:
 *
 *   [0]    bMessageType  — 0x6F for PC_to_RDR_XfrBlock
 *   [1-4]  dwLength      — payload length (LE uint32)
 *   [5]    bSlot         — always 0
 *   [6]    bSeq          — sequence number
 *   [7]    bBWI          — block waiting integer (0 for commands)
 *   [8-9]  wLevelParameter — 0x0000 for normal
 *   [10+]  abData        — APDU payload
 *
 * Bulk-in response header (10 bytes):
 *   [0]    bMessageType  — 0x80 for RDR_to_PC_DataBlock
 *   [1-4]  dwLength
 *   [5]    bSlot
 *   [6]    bSeq
 *   [7]    bStatus
 *   [8]    bError
 *   [9]    bChainParameter
 *   [10+]  abData        — response APDU
 */
class CCIDTransport {
  constructor(device) {
    this.device = device;
    this.seq = 0;
    this.endpointIn = null;
    this.endpointOut = null;
  }

  async open() {
    await this.device.open();

    // Find the CCID interface (class 0x0B)
    let iface = null;
    for (const cfg of this.device.configurations) {
      for (const i of cfg.interfaces) {
        for (const alt of i.alternates) {
          if (alt.interfaceClass === 0x0B) { iface = i; break; }
        }
        if (iface) break;
      }
      if (iface) break;
    }

    if (!iface) {
      // Fall back to first interface
      iface = this.device.configurations[0].interfaces[0];
    }

    await this.device.claimInterface(iface.interfaceNumber);

    const alt = iface.alternates[0];
    for (const ep of alt.endpoints) {
      if (ep.direction === 'in')  this.endpointIn  = ep.endpointNumber;
      if (ep.direction === 'out') this.endpointOut = ep.endpointNumber;
    }

    if (!this.endpointIn || !this.endpointOut) {
      throw new Error('Could not find CCID bulk endpoints');
    }
  }

  async close() {
    try { await this.device.close(); } catch (_) {}
  }

  /** Wrap an APDU in a CCID PC_to_RDR_XfrBlock message and send it. */
  async transmit(apduBytes) {
    const seq = this.seq++ & 0xFF;
    const len = apduBytes.length;
    const packet = new Uint8Array(10 + len);
    packet[0] = 0x6F;                           // PC_to_RDR_XfrBlock
    packet[1] = len & 0xFF;                     // dwLength (LE)
    packet[2] = (len >> 8) & 0xFF;
    packet[3] = (len >> 16) & 0xFF;
    packet[4] = (len >> 24) & 0xFF;
    packet[5] = 0x00;                           // bSlot
    packet[6] = seq;                            // bSeq
    packet[7] = 0x00;                           // bBWI
    packet[8] = 0x00;                           // wLevelParameter lo
    packet[9] = 0x00;                           // wLevelParameter hi
    packet.set(apduBytes, 10);

    await this.device.transferOut(this.endpointOut, packet);

    // Read response (may come in multiple USB packets)
    let response = new Uint8Array(0);
    while (true) {
      const result = await this.device.transferIn(this.endpointIn, 65536);
      const chunk = new Uint8Array(result.data.buffer);
      response = concatBytes(response, chunk);
      // CCID header tells us the expected payload length
      if (response.length >= 10) {
        const expectedLen = response[1] | (response[2] << 8) | (response[3] << 16) | (response[4] << 24);
        if (response.length >= 10 + expectedLen) break;
      }
    }

    if (response[0] !== 0x80) {
      throw new Error(`Unexpected CCID message type: 0x${response[0].toString(16)}`);
    }
    if (response[7] & 0x40) {
      throw new Error(`CCID error: bStatus=0x${response[7].toString(16)} bError=0x${response[8].toString(16)}`);
    }

    // Return just the APDU response (strip 10-byte CCID header)
    return response.slice(10);
  }
}

// ---------------------------------------------------------------------------
// Main YubiKeyOpenPGP class
// ---------------------------------------------------------------------------

class YubiKeyOpenPGP {
  constructor() {
    this.transport = null;
    this.device = null;
  }

  // Expose constants as static properties
  static get KEY_SLOT() { return KEY_SLOT; }
  static get DO_TAG() { return DO_TAG; }
  static get SW() { return SW; }
  static get hexToBytes() { return hexToBytes; }
  static get bytesToHex() { return bytesToHex; }
  static get tlv() { return tlv; }
  static get parseTLV() { return parseTLV; }
  static get concatBytes() { return concatBytes; }

  // -------------------------------------------------------------------------
  // Connection management
  // -------------------------------------------------------------------------

  /**
   * Prompt the user to select a YubiKey and open a connection.
   * Must be called from a user gesture (button click etc.)
   */
  async connect() {
    this.device = await navigator.usb.requestDevice({
      filters: [{ vendorId: YUBICO_VENDOR_ID }],
    });
    this.transport = new CCIDTransport(this.device);
    await this.transport.open();
  }

  /** Close the USB connection. */
  async disconnect() {
    if (this.transport) await this.transport.close();
    this.transport = null;
    this.device = null;
  }

  // -------------------------------------------------------------------------
  // Core APDU exchange
  // -------------------------------------------------------------------------

  /**
   * Send a command APDU and return the response data.
   * Automatically handles chained responses (SW1=0x61).
   * Throws on non-success status words.
   *
   * @returns {Uint8Array} Response data (without SW bytes)
   */
  async send(cla, ins, p1, p2, data = null, expectResponse = true) {
    const apdu = buildAPDU(cla, ins, p1, p2, data, expectResponse);
    let response = await this.transport.transmit(apdu);

    // Collect chained response data (SW1=0x61 means more data available)
    let allData = response.slice(0, response.length - 2);
    let sw1 = response[response.length - 2];
    let sw2 = response[response.length - 1];

    while (sw1 === 0x61) {
      // GET RESPONSE to retrieve remaining bytes
      const more = await this.transport.transmit(
        buildAPDU(0x00, 0xC0, 0x00, 0x00, null, true)
      );
      allData = concatBytes(allData, more.slice(0, more.length - 2));
      sw1 = more[more.length - 2];
      sw2 = more[more.length - 1];
    }

    const sw = (sw1 << 8) | sw2;

    if (sw !== SW.SUCCESS) {
      const err = new Error(`APDU error: SW=${sw.toString(16).toUpperCase().padStart(4,'0')}`);
      err.sw = sw;
      err.sw1 = sw1;
      err.sw2 = sw2;
      // Attach remaining PIN tries for wrong-PIN errors
      if (sw1 === 0x63) err.remainingTries = sw2 & 0x0F;
      throw err;
    }

    return allData;
  }

  // -------------------------------------------------------------------------
  // OpenPGP applet commands
  // -------------------------------------------------------------------------

  /**
   * SELECT the OpenPGP applet by AID.
   * Must be called before any other OpenPGP command.
   */
  async selectOpenPGPApplet() {
    // INS=0xA4 SELECT FILE, P1=0x04 select by AID, P2=0x00
    return this.send(0x00, 0xA4, 0x04, 0x00, OPENPGP_AID);
  }

  /**
   * GET DATA — read a Data Object by tag.
   *
   * @param {number} tag  - DO tag (1 or 2 bytes)
   * @returns {Uint8Array}
   */
  async getData(tag) {
    const p1 = (tag >> 8) & 0xFF;
    const p2 = tag & 0xFF;
    return this.send(0x00, 0xCA, p1, p2);
  }

  /**
   * PUT DATA — write a Data Object by tag.
   * Requires admin PIN to be verified first for most DOs.
   *
   * @param {number}     tag   - DO tag
   * @param {Uint8Array} value - New value
   */
  async putData(tag, value) {
    const p1 = (tag >> 8) & 0xFF;
    const p2 = tag & 0xFF;
    return this.send(0x00, 0xDA, p1, p2, value, false);
  }

  /**
   * VERIFY PIN.
   *
   * @param {string|Uint8Array} pin  - PIN as UTF-8 string or raw bytes
   * @param {'user'|'admin'} type    - 'user' (PW1) or 'admin' (PW3)
   */
  async verifyPIN(pin, type = 'user') {
    const pinBytes = typeof pin === 'string'
      ? new TextEncoder().encode(pin)
      : pin;
    // PW1 (user): P2=0x81 for signing, 0x82 for other ops
    // PW3 (admin): P2=0x83
    const p2 = type === 'admin' ? 0x83 : 0x82;
    return this.send(0x00, 0x20, 0x00, p2, pinBytes, false);
  }

  /**
   * CHANGE REFERENCE DATA (change PIN).
   *
   * @param {'user'|'admin'} type
   * @param {string} oldPIN
   * @param {string} newPIN
   */
  async changePIN(type, oldPIN, newPIN) {
    const p2 = type === 'admin' ? 0x83 : 0x81;
    const oldBytes = new TextEncoder().encode(oldPIN);
    const newBytes = new TextEncoder().encode(newPIN);
    return this.send(0x00, 0x24, 0x00, p2, concatBytes(oldBytes, newBytes), false);
  }

  /**
   * RESET RETRY COUNTER (unblock user PIN using admin PIN or Reset Code).
   *
   * @param {string} adminPIN
   * @param {string} newUserPIN
   */
  async resetUserPIN(adminPIN, newUserPIN) {
    // Must have admin PIN verified already, or provide it here via RESET RETRY
    // P1=0x02 means "with admin PIN", P2=0x81 = PW1
    const adminBytes = new TextEncoder().encode(adminPIN);
    const newBytes   = new TextEncoder().encode(newUserPIN);
    return this.send(0x00, 0x2C, 0x02, 0x81, concatBytes(adminBytes, newBytes), false);
  }

  // -------------------------------------------------------------------------
  // Key operations
  // -------------------------------------------------------------------------

  /**
   * GENERATE ASYMMETRIC KEY PAIR on card.
   * The key is generated on the YubiKey — private key never leaves.
   *
   * @param {number} slot  - KEY_SLOT.SIGN | DECRYPT | AUTH
   * @returns {Uint8Array} Public key data object (parse with parsePublicKey)
   */
  async generateKeyPair(slot) {
    const crt = new Uint8Array([slot, 0x00]);
    // INS=0x47, P1=0x80 (generate), P2=0x00
    return this.send(0x00, 0x47, 0x80, 0x00, crt);
  }

  /**
   * READ the public key for a slot without generating a new one.
   *
   * @param {number} slot  - KEY_SLOT.SIGN | DECRYPT | AUTH
   * @returns {Uint8Array} Public key data object
   */
  async getPublicKey(slot) {
    const crt = new Uint8Array([slot, 0x00]);
    // INS=0x47, P1=0x81 (read), P2=0x00
    return this.send(0x00, 0x47, 0x81, 0x00, crt);
  }

  /**
   * IMPORT a private key into a slot.
   *
   * Builds the Extended Header List (EHL) for key import per spec §7.2.14.
   * Requires admin PIN verified.
   *
   * @param {number}     slot       - KEY_SLOT.SIGN | DECRYPT | AUTH
   * @param {KeyMaterial} keyMaterial - See buildRSAKeyMaterial() / buildECKeyMaterial()
   */
  async importKey(slot, keyMaterial) {
    // Build the Extended Header List:
    // 7F48 (Private Key Template) → lists component tags and lengths
    // 5F48 (Concatenation of key data) → actual key bytes
    const { template, keyData } = keyMaterial;

    const body = concatBytes(
      tlv(0x7F48, template),  // Private Key Template
      tlv(0x5F48, keyData),   // Key data concatenation
    );
    const ehl = tlv(0x4D, concatBytes(new Uint8Array([slot, 0x00]), body));

    // INS=0xDB (PUT DATA — Odd), P1=0x3F, P2=0xFF
    return this.send(0x00, 0xDB, 0x3F, 0xFF, ehl, false);
  }

  /**
   * PSO:COMPUTE DIGITAL SIGNATURE — sign a hash with the signature key.
   * Requires user PIN (PW1 with P2=0x81) to be verified first.
   *
   * @param {Uint8Array} digestInfo  - DigestInfo structure (hash with ASN.1 prefix for RSA,
   *                                   or raw hash for ECDSA)
   * @returns {Uint8Array} Signature bytes
   */
  async sign(digestInfo) {
    // INS=0x2A PSO, P1=0x9E (digital signature), P2=0x9A (hash)
    return this.send(0x00, 0x2A, 0x9E, 0x9A, digestInfo);
  }

  /**
   * PSO:DECIPHER — decrypt data with the decryption key.
   * Requires user PIN (PW1 with P2=0x82) to be verified first.
   *
   * For RSA: prepend 0x00 padding indicator byte.
   * For ECDH: wrap in a TLV with tag 0xA6 / 0x7F49 / 0x86.
   *
   * @param {Uint8Array} ciphertext
   * @returns {Uint8Array} Plaintext
   */
  async decipher(ciphertext) {
    // Prepend 0x00 RSA padding indicator
    const data = concatBytes(new Uint8Array([0x00]), ciphertext);
    // INS=0x2A PSO, P1=0x80 (plain value), P2=0x86 (ciphertext)
    return this.send(0x00, 0x2A, 0x80, 0x86, data);
  }

  /**
   * INTERNAL AUTHENTICATE — authenticate with the auth key.
   * Requires user PIN (PW1 with P2=0x82) to be verified first.
   *
   * @param {Uint8Array} challenge  - Data to authenticate (hash or nonce)
   * @returns {Uint8Array} Authentication token / signature
   */
  async authenticate(challenge) {
    // INS=0x88 INTERNAL AUTHENTICATE
    return this.send(0x00, 0x88, 0x00, 0x00, challenge);
  }

  // -------------------------------------------------------------------------
  // Card info helpers
  // -------------------------------------------------------------------------

  /**
   * Read the Application Related Data (tag 6E).
   * Contains algorithm attributes, fingerprints, key info, etc.
   *
   * @returns {Map<number, Uint8Array>} Parsed TLV map
   */
  async getApplicationRelatedData() {
    const raw = await this.getData(0x006E);
    // The response itself is a constructed TLV — unwrap it
    const outer = parseTLV(raw);
    const inner = outer.get(0x6E) || raw;
    return parseTLV(inner);
  }

  /**
   * Read cardholder name, language, sex (tag 65).
   * @returns {Map<number, Uint8Array>}
   */
  async getCardholderData() {
    const raw = await this.getData(0x0065);
    const outer = parseTLV(raw);
    return parseTLV(outer.get(0x65) || raw);
  }

  /**
   * Read the three key fingerprints (60 bytes: 3 × 20 bytes).
   * @returns {{ sign: Uint8Array, decrypt: Uint8Array, auth: Uint8Array }}
   */
  async getFingerprints() {
    const data = await getApplicationRelatedData.call(this);
    const fp = data.get(0xC5);
    if (!fp || fp.length < 60) return null;
    return {
      sign:    fp.slice(0,  20),
      decrypt: fp.slice(20, 40),
      auth:    fp.slice(40, 60),
    };
  }

  /**
   * Write a key fingerprint to the card.
   * @param {number}     slot - KEY_SLOT constant
   * @param {Uint8Array} fingerprint - 20-byte SHA-1 fingerprint
   */
  async setFingerprint(slot, fingerprint) {
    const tagMap = {
      [KEY_SLOT.SIGN]:    DO_TAG.SIGN_FP,
      [KEY_SLOT.DECRYPT]: DO_TAG.DECRYPT_FP,
      [KEY_SLOT.AUTH]:    DO_TAG.AUTH_FP,
    };
    await this.putData(tagMap[slot], fingerprint);
  }

  /**
   * Write a key creation timestamp.
   * @param {number} slot      - KEY_SLOT constant
   * @param {Date}   timestamp - Key creation time
   */
  async setKeyTimestamp(slot, timestamp) {
    const tagMap = {
      [KEY_SLOT.SIGN]:    0x00CD,
      [KEY_SLOT.DECRYPT]: 0x00CE,
      [KEY_SLOT.AUTH]:    0x00CF,
    };
    const epoch = Math.floor(timestamp.getTime() / 1000);
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, epoch, false); // big-endian
    await this.putData(tagMap[slot], bytes);
  }

  /**
   * Set algorithm attributes for a key slot.
   * @param {number}     slot  - KEY_SLOT constant
   * @param {Uint8Array} attrs - Algorithm attributes bytes (see buildRSAAlgorithmAttrs)
   */
  async setAlgorithmAttributes(slot, attrs) {
    const tagMap = {
      [KEY_SLOT.SIGN]:    DO_TAG.ALGORITHM_ATTRS_SIGN,
      [KEY_SLOT.DECRYPT]: DO_TAG.ALGORITHM_ATTRS_DECRYPT,
      [KEY_SLOT.AUTH]:    DO_TAG.ALGORITHM_ATTRS_AUTH,
    };
    await this.putData(tagMap[slot], attrs);
  }
}

// ---------------------------------------------------------------------------
// Key material builders
// ---------------------------------------------------------------------------

/**
 * Build RSA algorithm attributes for PUT DATA.
 *
 * @param {number} bits         - Key size: 2048, 3072, or 4096
 * @param {number} eLen         - Public exponent length in bits (typically 17 or 32)
 * @param {number} format       - Import format: 0=standard, 2=CRT, 3=CRT+mod
 * @returns {Uint8Array}
 */
function buildRSAAlgorithmAttrs(bits = 2048, eLen = 17, format = 0x00) {
  return new Uint8Array([
    0x01,                       // Algorithm ID: RSA
    (bits >> 8) & 0xFF,         // modulus length hi
    bits & 0xFF,                // modulus length lo
    0x00,                       // public exponent length hi
    eLen,                       // public exponent length lo (17 bits = 0x11)
    format,                     // import/generate format
  ]);
}

/**
 * Build EC algorithm attributes.
 *
 * @param {'sign'|'decrypt'} usage
 * @param {string} oid  - OID bytes as hex (e.g. '2B 81 04 00 22' for P-384)
 *
 * Common OIDs:
 *   NIST P-256 (sign):   2A 86 48 CE 3D 03 01 07
 *   NIST P-384 (sign):   2B 81 04 00 22
 *   NIST P-521 (sign):   2B 81 04 00 23
 *   Curve25519 (decrypt):2B 06 01 04 01 DA 47 0F 01  (X25519)
 *   Ed25519 (sign):      2B 06 01 04 01 DA 47 0F 01  (same prefix, different usage)
 */
function buildECAlgorithmAttrs(usage, oidHex) {
  const algId = usage === 'decrypt' ? 0x12 : 0x13; // 0x12=ECDH, 0x13=ECDSA/EdDSA
  const oid = hexToBytes(oidHex);
  return concatBytes(new Uint8Array([algId]), oid, new Uint8Array([0xFF]));
  // 0xFF at end = standard import format
}

/**
 * Build RSA private key material for IMPORT KEY.
 *
 * The OpenPGP card spec §7.2.14 defines the Private Key Template (tag 7F48)
 * which lists component tags and their lengths, followed by the concatenated
 * key material (tag 5F48).
 *
 * Components for RSA CRT format:
 *   91 — e  (public exponent)
 *   92 — p  (prime factor)
 *   93 — q  (prime factor)
 *   94 — PQ = q^-1 mod p
 *   95 — DP1 = d mod (p-1)
 *   96 — DQ1 = d mod (q-1)
 *   97 — N  (modulus) — optional
 *
 * @param {Object} params  - RSA key components as Uint8Arrays
 *   { e, p, q, pq, dp1, dq1, n }
 *   All components should be the same byte length (keyBits/8 for n, keyBits/16 for p,q etc.)
 */
function buildRSAKeyMaterial({ e, p, q, pq, dp1, dq1, n }) {
  // Build template: each component tag + its length
  const components = [
    [0x91, e],
    [0x92, p],
    [0x93, q],
    [0x94, pq],
    [0x95, dp1],
    [0x96, dq1],
  ];
  if (n) components.push([0x97, n]);

  const templateParts = components.map(([tag, val]) =>
    concatBytes(new Uint8Array([tag]), berLength(val.length))
  );

  return {
    template: concatBytes(...templateParts),
    keyData:  concatBytes(...components.map(([, val]) => val)),
  };
}

/**
 * Build EC private key material for IMPORT KEY.
 *
 * Components:
 *   92 — private key scalar d
 *
 * @param {Uint8Array} privateKey  - Private key bytes
 */
function buildECKeyMaterial(privateKey) {
  return {
    template: concatBytes(new Uint8Array([0x92]), berLength(privateKey.length)),
    keyData:  privateKey,
  };
}

// ---------------------------------------------------------------------------
// DigestInfo builders (for PSO:SIGN with RSA PKCS#1 v1.5)
// ---------------------------------------------------------------------------

const DIGEST_INFO_PREFIX = {
  'SHA-1':   hexToBytes('30 21 30 09 06 05 2B 0E 03 02 1A 05 00 04 14'),
  'SHA-256': hexToBytes('30 31 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20'),
  'SHA-384': hexToBytes('30 41 30 0D 06 09 60 86 48 01 65 03 04 02 02 05 00 04 30'),
  'SHA-512': hexToBytes('30 51 30 0D 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40'),
};

/**
 * Build DigestInfo for RSA PKCS#1 v1.5 signing.
 *
 * @param {ArrayBuffer|Uint8Array} hash
 * @param {string} algorithm  - 'SHA-256', 'SHA-384', 'SHA-512'
 */
function buildDigestInfo(hash, algorithm = 'SHA-256') {
  const prefix = DIGEST_INFO_PREFIX[algorithm];
  if (!prefix) throw new Error(`Unknown digest algorithm: ${algorithm}`);
  return concatBytes(prefix, new Uint8Array(hash));
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

// For ES modules:
export {
  YubiKeyOpenPGP,
  buildRSAAlgorithmAttrs,
  buildECAlgorithmAttrs,
  buildRSAKeyMaterial,
  buildECKeyMaterial,
  buildDigestInfo,
  hexToBytes,
  bytesToHex,
  tlv,
  parseTLV,
  concatBytes,
  berLength,
  KEY_SLOT,
  DO_TAG,
  SW,
};

// For script tag / global usage:
if (typeof window !== 'undefined') {
  window.YubiKeyOpenPGP       = YubiKeyOpenPGP;
  window.YubiKeyHelpers = {
    buildRSAAlgorithmAttrs,
    buildECAlgorithmAttrs,
    buildRSAKeyMaterial,
    buildECKeyMaterial,
    buildDigestInfo,
    hexToBytes,
    bytesToHex,
    tlv,
    parseTLV,
    concatBytes,
    berLength,
    KEY_SLOT,
    DO_TAG,
    SW,
  };
}
