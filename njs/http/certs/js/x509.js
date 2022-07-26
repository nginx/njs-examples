function asn1_parse_oid(buf) {
    var oid = [];
    var sid = 0;
    var cur_octet = buf[0];

    if (cur_octet < 40) {
        oid.push(0);
        oid.push(cur_octet);

    } else if (cur_octet < 80) {
        oid.push(1);
        oid.push(cur_octet - 40);

    } else {
        oid.push(2);
        oid.push(cur_octet - 80);
    }

    for (var n = 1; n < buf.length; n++) {
        cur_octet = buf[n];

        if (cur_octet < 0x80) {
            sid += cur_octet;

            if (sid > Number.MAX_SAFE_INTEGER)
                throw "Too big SID value: " + sid;

            oid.push(sid);
            sid = 0;

        } else {
            sid += cur_octet & 0x7f; sid <<= 7;

            if (sid > Number.MAX_SAFE_INTEGER)
                throw "Too big SID value: " + sid;
        }
    }

    if (buf.slice(-1)[0] >= 0x80)
        throw "Last octet in oid buffer has highest bit set to 1";

    return oid.join('.')
}

function asn1_parse_integer(buf) {

    if (buf.length > 6) {
        // may exceed MAX_SAFE_INTEGER, lets return hex
        return asn1_parse_any(buf);
    }

    var value = 0;
    var is_negative = false;

    if (buf[0] & 0x80) {
        is_negative = true;
        value = buf[0] & 0x7f;
        var compl_int = 1 << (8 * buf.length - 1)

    } else {
        value = buf[0];
    }

    if (buf.length > 1) {
        for (var n = 1; n < buf.length; n++) {
            value <<= 8;
            value += buf[n];
        }
    }

    if (is_negative)
        return value - compl_int;
    else
        return value;
}

function asn1_parse_ascii_string(buf) {
    return buf.toString();
}

function asn1_parse_ia5_string(buf) {
    if (is_ia5(buf))
        return buf.toString();
    else
        throw "Not a IA5String: " + buf;
}

function asn1_parse_utf8_string(buf) {
    return buf.toString('utf8');
}

function asn1_parse_bmp_string(buf) {
    return asn1_parse_any(buf)
}

function asn1_parse_universal_string(buf) {
    return asn1_parse_any(buf)
}

function asn1_parse_bit_string(buf) {
    if (buf[0] == 0)
        return buf.slice(1).toString("hex");

    var shift = buf[0]
    if (shift > 7)
        throw "Incorrect shift in bitstring: " + shift;

    var value = "";
    var upper_bits = 0;
    var symbol = "";

    // shift string right and convert to hex
    for (var n = 1; n < buf.length; n++) {
         var char_code = buf[n] >> shift + upper_bits;
         symbol = char_code.toString(16);
         upper_bits = (buf[n] << shift) & 0xff;
         value += symbol;
    }

    return value;
}

function asn1_parse_octet_string(buf) {
    return asn1_parse_any(buf)
}

function asn1_parse_any(buf) {
    return buf.toString('hex')
}

function is_ia5(buf) {
    for (var n = 0; n < buf.length; n++) {
        var s = buf[n];
        if (s > 0x7e)
            return false;
    }

    return true;
}

function asn1_read_length(buf, pointer) {
    var s = buf[pointer];
    if (s == 0x80 || s == 0xff)
        throw "indefinite length is not supported"

    if (s < 0x80) {
        // length is less than 128
        pointer++;
        return [s, pointer];

    } else {
        var l = s & 0x7f;
        if (l > 7)
            throw "Too big length, exceeds MAX_SAFE_INTEGER: " + l;

        if ((pointer + l) >= buf.length)
            throw "Went out of buffer: " + (pointer + l) + " " + buf.length;

        var length = 0;
        for (var n = 0; n < l; n++) {
            length += Math.pow(256, l - n - 1) * buf[++pointer];
            if (n == 6 && buf[pointer] > 0x1f)
                throw "Too big length, exceeds MAX_SAFE_INTEGER";
        }

        return [length, pointer + 1];
    }
}

function asn1_parse_primitive(cls, tag, buf) {
    if (cls == 0) {
        switch(tag) {
        // INTEGER
        case 0x02: return asn1_parse_integer(buf);
        // BIT STRING
        case 0x03:
           try {
               return asn1_read(buf);
           } catch(e) {
               return asn1_parse_bit_string(buf);
           }
        // OCTET STRING
        case 0x04:
           try {
               return asn1_read(buf);
           } catch(e) {
               return asn1_parse_octet_string(buf);
           }
        // OBJECT IDENTIFIER
        case 0x06: return asn1_parse_oid(buf);
        // UTF8String
        case 0x0c: return asn1_parse_utf8_string(buf);
        // TIME
        case 0x0e:
        // NumericString
        case 0x12:
        // PrintableString
        case 0x13:
        // T61String
        case 0x14:
        // VideotexString
        case 0x15:
           return asn1_parse_ascii_string(buf);
        // IA5String
        case 0x16: return asn1_parse_ia5_string(buf);
        // UTCTime
        case 0x17:
        // GeneralizedTime
        case 0x18:
        // GraphicString
        case 0x19:
        // VisibleString
        case 0x1a:
        // GeneralString
        case 0x1b:
           return asn1_parse_ascii_string(buf);
        // UniversalString
        case 0x1c: return asn1_parse_universal_string(buf);
        // CHARACTER STRING
        case 0x1d: return asn1_parse_ascii_string(buf);
        // BMPString
        case 0x1e: return asn1_parse_bmp_string(buf);
        // DATE
        case 0x1f:
        // TIME-OF-DAY
        case 0x20:
        // DATE-TIME
        case 0x21:
        // DURATION
        case 0x22:
           return asn1_parse_ascii_string(buf);
        default: return asn1_parse_any(buf);
        }

    } else if (cls == 2) {
        switch(tag) {
        case 0x00: return asn1_parse_any(buf);
        case 0x01: return asn1_parse_ascii_string(buf);
        case 0x02: return asn1_parse_ascii_string(buf);
        case 0x06: return asn1_parse_ascii_string(buf);
        default: return asn1_parse_any(buf);
        }
    }

    return asn1_parse_any(buf);
}

function asn1_read(buf) {
    var a = [];
    var tag_class;
    var tag;
    var pointer = 0;
    var is_constructed;
    var s = "";
    var length;

    while (pointer < buf.length) {
        // read type: 7 & 8 bits define class, 6 bit if it is constructed
        s = buf[pointer];
        tag_class = s >> 6;
        is_constructed = s & 0x20;
        tag = s & 0x1f;

        if (tag == 0x1f) {
            tag = 0;
            var i = 0;

            do {
                if (i > 3)
                    throw "Too big tag value" + tag;

                i++;

                if (++pointer >= buf.length)
                    throw "Went out of buffer: " + pointer + " " + buf.length;

                tag <<= 7;
                tag += (buf[pointer] & 0x7f);

            } while (buf[pointer] > 0x80)
        }

        if (++pointer > buf.length)
             throw "Went out of buffer: " + pointer + " " + buf.length;

        var lp = asn1_read_length(buf, pointer);
        length = lp[0];
        pointer = lp[1];

        if ((pointer + length) > buf.length)
             throw "length exceeds buf side: " + length + " " + pointer + " "
                 +  buf.length;

        if (is_constructed) {
            a.push(asn1_read(buf.slice(pointer, pointer + length)));

        } else {
            a.push(asn1_parse_primitive(tag_class, tag,buf.slice(pointer, pointer + length)));
        }

        pointer += length;
    }

    return a;
}

function is_oid_exist(cert, oid) {
    for (var n = 0; n < cert.length; n++) {
        if (Array.isArray(cert[n])) {
            if (is_oid_exist(cert[n], oid))
                return true;

        } else {
            if (cert[n] == oid)
                return true;
        }
    }

    return false;
}

// returns all the matching field with the specified 'oid' as a list
function get_oid_value_all(cert, oid) {
    var values = [];

    for (var n = 0; n < cert.length; n++) {
        if (Array.isArray(cert[n])) {
            var r = get_oid_value_all(cert[n], oid);
            if (r.length > 0) {
            values = values.concat(r);
            }
        } else {
            if (cert[n] == oid) {
                if (n < cert.length) {
                    // push next element in array
                    values.push(cert[n+1]);
                }
            }
        }
    }

    return values;
}

function get_oid_value(cert, oid) {
    for (var n = 0; n < cert.length; n++) {
        if (Array.isArray(cert[n])) {
            var r = get_oid_value(cert[n], oid);
            if (r !== false)
                return r;

        } else {
            if (cert[n] == oid) {
                if (n < cert.length) {
                    // return next element in array
                    return cert[n+1];
                }
            }
        }
    }

    return false;
}

function parse_pem_cert(pem) {
    var der = pem.split(/\n/);

    if (pem.match('CERTIFICATE')) {
        der = der.slice(1, -2);
    }

    return asn1_read(Buffer.from(der.join(''), 'base64'));
}

export default {asn1_read, parse_pem_cert, is_oid_exist, get_oid_value, get_oid_value_all};
