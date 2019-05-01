/*
 * test.js
 * cryptopals solutions testing suite
 */

let assert = require('assert');
let fs     = require('fs');

let set1 = require('./set1.js');
let set2 = require('./set2.js');

let testsets = [
    set1.tests,
    set2.tests
];

console.log('starting cryptopals tests..');

let successes = 0;
let failures  = 0;

let challenge_ind = 1;

testsets.forEach((tests, set_ind) => {
    set_ind++; /* start indices at 1 */

    console.log('testing challenge set ' + set_ind);
    tests.forEach(test => {
        let challenge = set_ind + '.' + challenge_ind;
        console.log('running tests for ' + challenge);

        try {
            test();
            successes++;
        } catch (e) {
            console.log(challenge + ' FAILED: ' + e);
            failures++;
        }

        challenge_ind++;
    });
});

console.log('done testing. ' + successes + ' OK, ' + failures + ' failures');
