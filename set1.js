/*
 * set1.js
 *
 * cryptopals set 1
 */

let assert = require('assert');
let crypto = require('crypto');
let fs     = require('fs');

let set1 = {};

set1.tests = [];

/*
 * 1.1 - Convert hex to base64
 *
 * hex_to_b64 takes a hex string argument and returns the base64 encoding
 */

set1.hex_to_b64 = (x) => Buffer.from(x, 'hex').toString('base64');

set1.tests.push(() => {
    let input = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d';
    let out   = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t';

    assert.equal(set1.hex_to_b64(input), out);
});

/*
 * 1.2 - Fixed XOR
 *
 * fixed_xor takes two buffers and produces their XOR
 */

set1.fixed_xor = (a, b) => {
    if (a.length != b.length) {
        return null;
    }

    let out = Buffer.alloc(a.length);

    for (var i = 0; i < a.length; ++i) {
        out[i] = a[i] ^ b[i];
    }

    return out;
};

set1.tests.push(() => {
    let a = Buffer.from('1c0111001f010100061a024b53535009181c', 'hex');
    let b = Buffer.from('686974207468652062756c6c277320657965', 'hex');
    let expected = '746865206b696420646f6e277420706c6179';
    
    assert.equal(set1.fixed_xor(a, b).toString('hex'), expected);
});

/*
 * 1.3 - Single-byte XOR cipher
 *
 * analyze_single_byte_xor(x) accepts a ciphertext buffer,
 * and returns the most sensible (high-scoring) plaintext buffer
 */

set1.analyze_single_byte_xor = (ct) => {
    /* grab plaintexts for each possible byte */
    let plaintexts = [...Array(256).keys()].map(b => {
        let xor_buf = Buffer.alloc(ct.length).fill(b);
        return { key: b, buf: set1.fixed_xor(ct, xor_buf) };
    });

    /* score each plaintext */
    plaintexts = plaintexts.map(x => {
        x.score = set1.score_plaintext(x.buf);
        return x;
    });

    /* sort the results by descending score */
    plaintexts.sort((a, b) => b.score - a.score);

    /* return the best plaintext */
    return plaintexts[0];
};

set1.tests.push(() => {
    let input = Buffer.from('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736', 'hex');
    let expected = "Cooking MC's like a pound of bacon"

    assert.equal(set1.analyze_single_byte_xor(input).buf.toString(), expected);
});

/*
 * score_plaintext(p) accept a plaintext buffer object, and returns a numeric
 * 'score' based on standard English character frequencies
 */

set1.score_plaintext = (pt) => {
    /* strings containing bad chars don't need to be scored */
    if (!/^[\x00-\x7F]*$/.test(pt.toString())) {
        return 0;
    }

    /* 
     * standard letter frequencies, collected from
     * http://pi.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
     */
    let standard_frequencies = [
        0.0812, 0.0149, 0.0271, 0.0432, 0.1202, 0.0230, 0.0203, 0.0592, 0.0731, /* A-I */
        0.0010, 0.0069, 0.0398, 0.0261, 0.0695, 0.0768, 0.0182, 0.0011, 0.0602, /* J-R */
        0.0628, 0.0910, 0.0288, 0.0111, 0.0209, 0.0017, 0.0211, 0.0007, 0.1300  /* S-Z, ' ' */
    ];

    /* squash the input into the relevant letters */
    let letters = pt.toString().toLowerCase().replace(/[^a-z ]/g, '');
    let score = 0;

    for (var i = 0; i < letters.length; ++i) {
        if (letters.charAt(i) == ' ') {
            score += standard_frequencies[26];
        } else {
            score += standard_frequencies[letters.charCodeAt(i) - 'a'.charCodeAt(0)];
        }
    }

    return score;
};

/*
 * 1.4 - Detect single-character XOR
 *
 * detect_single_char_xor(a) accepts an array of ciphertext buffers,
 * tries to decode each of them via (1.3), and returns the one that decoded most 'successfully'
 * (the one with the highest plaintext score)
 */

set1.detect_single_char_xor = (buflist) => {
    /* decode each buffer, score each plaintext, and return the best scoring one */

    return buflist.map(x => set1.analyze_single_byte_xor(x))
                  .sort((a, b) => b.score - a.score)[0].buf; /* damn, fp is cool */
};

set1.tests.push(() => {
    let buflist = fs.readFileSync('4.txt').toString().split('\n').map(x => Buffer.from(x, 'hex'));
    let result = set1.detect_single_char_xor(buflist);
    let expected = 'Now that the party is jumping\n';

    assert.equal(result.toString(), expected);
});

/*
 * 1.5 - Implement repeating-key XOR
 *
 * repeated_key_xor(b, key) encrypts b with <key> using repeated-key xor and returns the ciphertext buffer
 */

set1.repeated_key_xor = (pt, key) => {
    let out = Buffer.alloc(pt.length);
    let key_pos = 0;

    for (var i = 0; i < pt.length; ++i) {
        out[i] = pt[i] ^ key[key_pos++ % key.length];
    }

    return out;
};

set1.tests.push(() => {
    let inp = Buffer.from("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
    let key = Buffer.from('ICE');
    let res = set1.repeated_key_xor(inp, key);
    let expected = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f';

    assert.equal(res.toString('hex'), expected);
});

/*
 * 1.6 - Break repeating-key XOR
 *
 * decode_repeated_xor(d) accepts a ciphertext buffer and tries to decrypt it,
 * returning the highest scoring plaintext buffer
 */

set1.decode_repeated_xor = (ct) => {
    /*
     * first, try and guess the key length
     * try values from 2-40 bytes and get a taste of how well they fit by looking at normalized hamming distances
     */

    let key_sizes = [];
    let results = [];

    for (var i = 2; i <= 40; ++i) {
        /* grab a couple chunks of ciphertext */
        let first_chunk = Buffer.from(ct, 0, i);
        let second_chunk = Buffer.from(ct, i, i);

        /* compute their normalized distance */
        let dist = set1.hamming_distance(first_chunk, second_chunk) / i;

        key_sizes.push({ length: i, dist: dist });
    }

    /* order key sizes by ascending normalized distance */
    key_sizes.sort((a, b) => a.dist - b.dist);

    for (var i = 0; i < key_sizes.length; ++i) {
        let key_size = key_sizes[i].length;

        /* duplicate the ciphertext buffer so we can divide it */
        let buf = Buffer.allocUnsafe(ct.length);
        ct.copy(buf);

        /* break ciphertext into chunks of key length */
        let chunks = [];

        while (buf.length) {
            chunks.push(buf.slice(0, key_size));
            buf = buf.slice(key_size);
        }

        /* transpose chunks */
        let transposed_chunks = [];

        for (var ki = 0; ki < key_size; ++ki) {
            let bytes = [];

            chunks.forEach(c => {
                bytes.push(c[ki]);
            });

            transposed_chunks.push(Buffer.from(bytes));
        }

        /* perform fixed XOR analysis to try and extract the key bytes */
        let chunk_results = transposed_chunks.map(x => set1.analyze_single_byte_xor(x));

        /* now, recombine the chunk results to construct the key (maybe) */
        let key = [];

        chunk_results.forEach(x => key.push(x.key));
        key = Buffer.from(key);

        /* with the possible key, try decrypting the ciphertext and store the result */
        let pt = set1.repeated_key_xor(ct, key);
        let pt_score = set1.score_plaintext(pt);

        results.push({
            pt: pt,
            score: pt_score,
            key: key,
        });
    }

    /* sort the results by the highest score */
    results.sort((a, b) => b.score - a.score);

    /* return the best one. all done! */
    return results[0];
};

set1.tests.push(() => {
    let input = Buffer.from(fs.readFileSync('6.txt').toString(), 'base64')
    let result = set1.decode_repeated_xor(input);
    let expected_key = 'Terminator X: Bring the noise';

    assert.equal(result.key.toString(), expected_key);
});

/*
 * hamming_distance(a, b) computes the hamming distance between two strings.
 */

set1.hamming_distance = (a, b) => {
    /* number of differing bits in each character */

    if (a.length != b.length) {
        return null;
    }

    let dist = 0;

    for (var i = 0; i < a.length; ++i) {
        /* the edit distance is the summation of the popcnts of the bitwise XOR */
        let diff = a[i] ^ b[i];

        while (diff) {
            dist += (diff & 1);
            diff /= 2;
        }
    }

    return dist;
};

/*
 * 1.7 - AES in ECB mode
 *
 * ecb_encrypt(pt, key) and ecb_decrypt(ct, key) provide encryption and decryption in ecb mode
 */

set1.ecb_encrypt = (pt, key) => {
    let cip = crypto.createCipheriv('aes-128-ecb', key, '');
    cip.setAutoPadding(false);
    return Buffer.concat([cip.update(pt), cip.final()]);
}

set1.ecb_decrypt = (ct, key) => {
    let cip = crypto.createDecipheriv('aes-128-ecb', key, '');
    cip.setAutoPadding(false);
    return Buffer.concat([cip.update(ct), cip.final()]);
}

set1.tests.push(() => {
    let inp_data = Buffer.from(fs.readFileSync('7.txt').toString(), 'base64');
    let res = set1.ecb_decrypt(inp_data, Buffer.from('YELLOW SUBMARINE'));
    let first_line = "I'm back and I'm ringin' the bell "

    assert.equal(res.toString().split('\n')[0], first_line);
});

/*
 * 1.8 - Detect AES in ECB mode
 *
 * detect_aes_ecb(ctlist) accepts an array of ciphertext buffers and returns
 * an array of ciphertexts that may be encrypted in ecb mode.
 */

set1.detect_aes_ecb = (ctlist) => {
    /* modern ciphers will NEVER produce repeating blocks (or even similar-looking blocks).
     * any identical blocks is a dead giveaway for ECB mode */

    let output = [];

    ctlist.forEach(ct => {
        /* first, split the ct into views of each block */
        let blocks = [];
        let orig_ct = ct;

        while (ct.length) {
            blocks.push(ct.slice(0, 16));
            ct = ct.slice(16);
        }

        /* scan for matching blocks */
        for (var i = 0; i < blocks.length; ++i) {
            for (var j = i + 1; j < blocks.length; ++j) {
                if (blocks[i].compare(blocks[j]) == 0) {
                    output.push(orig_ct);
                    return;
                }
            }
        }
    });

    return output;
};

set1.tests.push(() => {
    let ctlist = fs.readFileSync('8.txt').toString().split('\n').map(x => Buffer.from(x, 'hex'));
    let res = set1.detect_aes_ecb(ctlist);

    assert.equal(res.length, 1);
});

module.exports = set1;
