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

    if (num_bytes > 0 || b.length == 0) {
        num_bytes = block_size - num_bytes; /* right-align padding boundary */
        let padbuf = Buffer.allocUnsafe(num_bytes);
        padbuf.fill(num_bytes);
        pad.push(padbuf);
    }

    return Buffer.concat(pad);
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

    return Buffer.concat(pt_blocks);
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

    console.log('deduced block size ' + block_size);

    /* with the block size known, we verify that the cipher is in ECB mode.
     * this is very straightforward, we inject two identical plaintext blocks
     * and then check the ciphertext */

    pt = Buffer.alloc(block_size * 2);
    let mode_detect_ct = oracle(pt);

    if (mode_detect_ct.slice(0, block_size).compare(mode_detect_ct.slice(block_size, 2 * block_size)) != 0) {
        /* not ECB, cannot continue */
        throw 'Oracle is not encrypting in ECB mode!';
    }

    console.log('detected ecb mode');

    /* our decryption function works because we can keep the original ciphertext
     * and use it to compare against some clever inputs to the oracle.
     *
     * we can extract a single byte at a time by constructing a lookup table for each
     * ciphertext position.
     *
     * as we collect the hidden bytes we need to reuse them to collect more.
     *
     * slowly but surely scan through the ciphertext! */

    let result = [];
    let dict = {};

    let cur_block = Buffer.alloc(block_size);
    let out_buf = Buffer.alloc(0);
    let target_block = 0;
    let num_blocks = ctlen / block_size;

    console.log('cracking ' + num_blocks + ' blocks');

    while (target_block < ctlen) {
        /* attack the ith block of the ciphertext */
        let 
    }
};

set2.tests.push(() => {
    let res = set2.crack_oracle_2(set2.encryption_oracle_2);
});

module.exports = set2;
