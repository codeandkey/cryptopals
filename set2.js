/*
 * set2.js
 *
 * cryptopals set 2
 */

let assert = require('assert');
let crypto = require('crypto');
let fs     = require('fs');

let set1 = require('./set1.js');

let set2 = {};

set2.tests = [];

/*
 * 2.9 - Implement PKCS#7 padding
 *
 * pad_pkcs7(b, block_size) applies PKCS#7 padding to b, returning a new buffer
 */

set2.pad_pkcs7 = (b, block_size) => {
    let num_bytes = b.length % block_size;
    let pad = [b];

    num_bytes = block_size - num_bytes; /* right-align padding boundary */
    let padbuf = Buffer.allocUnsafe(num_bytes);
    padbuf.fill(num_bytes);
    pad.push(padbuf);

    return Buffer.concat(pad);
};

set2.unpad_pkcs7 = (b) => {
    /* read the last byte, and remove that many bytes from the end */
    let len = b[b.length - 1];
    return b.slice(0, -len);
};

set2.tests.push(() => {
    let inp = Buffer.from('YELLOW SUBMARINE');
    let bsize = 20;
    let expected = 'YELLOW SUBMARINE\x04\x04\x04\x04';

    assert.equal(set2.pad_pkcs7(inp, bsize).toString(), expected);
});

/*
 * 2.10 - Implement CBC mode
 *
 * like ECB mode, cbc mode is provided through cbc_encrypt(pt, key, iv) and cbc_decrypt(pt, key, iv)
 */

set2.cbc_encrypt = (pt, key, iv) => {
    /* implement the chaining ourself! we have access to ecb mode which is plenty */

    let last_ct = iv;
    let ct_blocks = [];
    let block_size = 16;

    /* apply padding to normalize block sizes */
    pt = set2.pad_pkcs7(pt, block_size);

    while (1) {
        if (pt.length == 0) {
            break;
        }

        let pt_block = pt.slice(0, block_size);
        pt = pt.slice(block_size);

        last_ct = set1.ecb_encrypt(set1.fixed_xor(last_ct, pt_block), key);
        ct_blocks.push(last_ct);
    }

    return Buffer.concat(ct_blocks);
}

set2.cbc_decrypt = (ct, key, iv) => {
    let last_ct = iv;
    let pt_blocks = [];
    let block_size = 16;

    if (ct.length % block_size) {
        throw 'Invalid ciphertext size ' + ct.length + ', not multiple of block size ' + block_size;
    }

    while (1) {
        if (ct.length < block_size) {
            /* no more blocks */
            break;
        }

        let ct_block = ct.slice(0, block_size);
        ct = ct.slice(block_size);

        let pt_block = set1.fixed_xor(last_ct, set1.ecb_decrypt(ct_block, key));

        last_ct = ct_block;
        pt_blocks.push(pt_block);
    }

    return set2.unpad_pkcs7(Buffer.concat(pt_blocks));
}

set2.tests.push(() => {
    let inp = Buffer.from(fs.readFileSync('10.txt').toString(), 'base64')
    let key = Buffer.from('YELLOW SUBMARINE');
    let iv  = Buffer.alloc(16);

    let res = set2.cbc_decrypt(inp, key, iv);
    assert.equal(res.toString().split('\n')[0], "I'm back and I'm ringin' the bell ");

    /* verify encryption too */
    let value = Buffer.from('encryption block');
    iv = Buffer.alloc(16);
    key = Buffer.alloc(16);

    crypto.randomFillSync(iv);
    crypto.randomFillSync(key);

    let res2 = set2.cbc_decrypt(set2.cbc_encrypt(value, key, iv), key, iv);

    assert.equal(value.toString(), res2.toString());
});

/*
 * 2.11 - An ECB/CBC detection oracle
 */

set2.encryption_oracle = (b) => {
    let prefix = Buffer.alloc(5 + Math.floor(Math.random() * 6));
    let suffix = Buffer.alloc(5 + Math.floor(Math.random() * 6));

    crypto.randomFillSync(prefix);
    crypto.randomFillSync(suffix);

    let warped_plaintext = set2.pad_pkcs7(Buffer.concat([prefix, b, suffix]), 16);

    let key = Buffer.alloc(16);
    let iv = Buffer.alloc(16);

    crypto.randomFillSync(key);
    crypto.randomFillSync(iv);

    if (Math.random() < 0.5) {
        return { ct: set1.ecb_encrypt(warped_plaintext, key), mode: 'ecb' };
    } else {
        return { ct: set2.cbc_encrypt(warped_plaintext, key, iv), mode: 'cbc' };
    }
};

/*
 * detect_ecb_or_cbc accepts a function with implements the challenge oracle,
 * and detects whether it used ecb or cbc mode.
 *
 * will throw an exception if the guess is incorrect.
 */

set2.detect_ecb_or_cbc = (oracle) => {
    /* generate a large block of data. we don't need to vary this -- we can just use 128 bytes every time */
    /* 128 adjacent bytes (8 blocks) will guarantee a minimum of 7 identical blocks towards the center if the oracle uses ECB */

    let block_size = 16;
    let payload_blocks = 8;
    let inp = Buffer.alloc(payload_blocks * block_size);
    let res = oracle(inp);

    let res_blocks = [];

    /* slice into blocks */
    while (res.ct.length) {
        res_blocks.push(res.ct.slice(0, block_size));
        res.ct = res.ct.slice(block_size);
    }

    /* track how many matching adjacent blocks we get */
    let max_adjacent_blocks = 1;
    let current_block = res_blocks[0];
    let current_adj_length = 1;

    for (var i = 1; i < res_blocks.length; ++i) {
        if (res_blocks[i].compare(current_block) == 0) {
            if (++current_adj_length > max_adjacent_blocks) {
                max_adjacent_blocks = current_adj_length;
            }
        } else {
            current_adj_length = 1;
        }

        current_block = res_blocks[i];
    }

    /* guess CBC if we couldn't find enough blocks, ECB otherwise */
    let guess = 'cbc';
    if (max_adjacent_blocks >= payload_blocks - 1) {
        guess = 'ecb';
    }

    if (guess != res.mode) {
        throw 'Guessed ' + guess + ' but oracle claims ' + res.mode;
    }
};

set2.tests.push(() => {
    for (var i = 0; i < 100; ++i) {
        set2.detect_ecb_or_cbc(set2.encryption_oracle);
    }
});

/*
 * 2.12 - Byte-at-a-time ECB decryption (Simple)
 */

/* we need a random, global key for this challenge */
set2.p12_key = Buffer.alloc(16); 
crypto.randomFillSync(set2.p12_key);

set2.encryption_oracle_2 = (b) => {
    /* don't decode it -- spoilers */
    let suffix = Buffer.from('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBte' +
                             'SByYWctdG9wIGRvd24gc28gbXkgaGFpci' +
                             'BjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiB' +
                             'zdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNh' + 
                             'eSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJI' +
                             'Gp1c3QgZHJvdmUgYnkK', 'base64');

    let pt = set2.pad_pkcs7(Buffer.concat([b, suffix]), 16);
    return set1.ecb_encrypt(pt, set2.p12_key);
};

set2.crack_oracle_2 = (oracle) => {
    /* figure out block size. the idea is to increase the input size until it
     * crosses a padding boundary. then the ciphertext will increase in size
     * by exactly one block. (regardless of mode) */

    let pt = '';
    let ctlen = oracle(Buffer.from(pt)).length;
    let block_size = 0;

    while (true) {
        pt += ' ';
        let curlen = oracle(Buffer.from(pt)).length;

        if (curlen > ctlen) {
            block_size = curlen - ctlen;
            break;
        }
    }

    /* with the block size known, we verify that the cipher is in ECB mode.
     * this is very straightforward, we inject two identical plaintext blocks
     * and then check the ciphertext */

    pt = Buffer.alloc(block_size * 2);
    let mode_detect_ct = oracle(pt);

    if (mode_detect_ct.slice(0, block_size).compare(mode_detect_ct.slice(block_size, 2 * block_size)) != 0) {
        /* not ECB, cannot continue */
        throw 'Oracle is not encrypting in ECB mode!';
    }

    /*
     * the oracle attack works by injecting plaintext blocks of varying length to
     * influence the block boundaries. we can also encrypt arbitrary plaintexts using
     * the hidden key -- this allows us to retrieve one byte at a time using the
     * block boundary to reduce the brute-force complexity for 1 byte to 2^8.
     */

    let last_block = Buffer.alloc(block_size);
    let output = Buffer.alloc(0);
    let target_block = 0;
    let num_blocks = ctlen / block_size;

    process.stdout.write('deciphering plaintext: ');

    for (let block = 0; block < num_blocks; ++block) {
        /* attack the ith block of the ciphertext */
        let inject_block = Buffer.alloc(block_size);
        let cracked_block = Buffer.alloc(0);

        for (let i = 0; i < block_size; ++i) {
            /* drop a byte from the injecting block */
            inject_block = inject_block.slice(1);

            /* 
             * construct the dictionary for the last byte
             * the dictionary should be all of the data (of length block_size - 1)
             * IMMEDIATELY before the target byte.
             * fortunately at this point we already know all of those bytes!
             * take all of the bytes we've cracked so far, append them to the previous block.
             * then shorten the left side until it matches block_size - 1
             */

            let dict_input_prefix = Buffer.concat([last_block, cracked_block]).slice(1 - block_size);
            let dict = {};

            for (let b = 0; b < 256; ++b) {
                let dict_building_input = Buffer.concat([dict_input_prefix, Buffer.from([b])]);
                let dict_building_output = oracle(dict_building_input).slice(0, block_size).toString('hex');

                dict[dict_building_output] = b;
            }

            /*
             * now with the dictionary, we just need to inject some input and
             * keep the output. the values of our inject block only matter for the first
             * target block. for all of the others, we already know the plaintext --
             * only the length matters so we can influence the boundary locations.
             *
             * we CAN'T use the dict input prefix as the injecting block because it will always
             * be the same length. here we can just know that our injected values will always be 0x00
             * and set the initial value of last_block accordingly.
             */

            let block_result = oracle(inject_block).slice(block_size * block, block_size * (block + 1));
            let byte_result = dict[block_result.toString('hex')];

            if (typeof byte_result === 'undefined') {
                /* 
                 * if no dictionary matches, we have read past the last block.
                 * this will always happen towards the end due to the padding changing
                 * while we are cracking bytes. fortunately, the last padding byte will always be a 0x1
                 * immediately before the first dictionary failure. we can just stop here and let the unpadding
                 * process continue as normal, stripping off the last byte.
                 */

                break;
            }

            /* we stole a byte! push it to the cracked block */
            cracked_block = Buffer.concat([cracked_block, Buffer.from([byte_result])]);

            process.stdout.write(Buffer.from([byte_result]).toString());
        }

        /* block has been completely revealed! concatenate it with the output */
        output = Buffer.concat([output, cracked_block]);

        /* store it in last_block so we can use it for the next dictionary attack */
        last_block = cracked_block;
    }

    process.stdout.write('\n');

    return set2.unpad_pkcs7(output);
};

set2.tests.push(() => {
    let res = set2.crack_oracle_2(set2.encryption_oracle_2);
    let expected = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFp' +
                   'ciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq' +
                   'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK';

    assert.equal(res.toString('base64'), expected);
});

/*
 * 2.13 - ECB cut-and-paste
 */

set2.profile_for = (email) => {
    /* don't allow user to inject their own keys */
    email = email.replace('&', '');
    email = email.replace('=', '');

    /* construct the encoding */
    return 'email=' + email + '&uid=10&role=user';
};

set2.parse_profile = (s) => {
    let keys = s.split('&');
    let out = {};

    keys.forEach(k => {
        let pair = k.split('=');

        if (pair.length != 2) {
            throw 'Invalid profile key ' + k + ' in ' + s;
        }

        out[pair[0]] = pair[1];
    });

    return out;
};

/* need another random key for 2.13 */
set2.s2_13_key = Buffer.alloc(16);
crypto.randomFillSync(set2.s2_13_key);

set2.encrypt_profile = (p) => {
}

module.exports = set2;
