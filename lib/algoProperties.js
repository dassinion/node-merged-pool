var bignum = require('bignum');
var multiHashing = require('unomp-multi-hashing-sd');
var util = require('./util.js');

var diff1 = global.diff1 = 0x00000000ffff0000000000000000000000000000000000000000000000000000;

var algos = module.exports = global.algos = {
    sha256: {
        //Uncomment diff if you want to use hardcoded truncated diff
        //diff: '00000000ffff0000000000000000000000000000000000000000000000000000',
        hash: function(){
            return function(){
                return util.sha256d(data);
            }
        }
    },
    'lyra2re': {
        multiplier: Math.pow(2, 7),
        hash: function(){
            return function(data){
                return multiHashing.lyra2re(data);
            }
        }
    },
    'lyra2rev2': {
        multiplier: Math.pow(2, 8),
        hash: function(){
            return function(data){
                return multiHashing.lyra2rev2(data);
            }
        }
    },
    'lyra2v2': {
        multiplier: Math.pow(2, 7),
        hash: function(){
            return function(data){
                return multiHashing.lyra2v2(data);
            }
        }
    },
    'phi1612': {
        hash: function(){
            return function(data){
                return multiHashing.phi1612(data);
            }
        }
    },
    'equihash': {
        multiplier: 1,
        diff: parseInt('0x0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'),
        hash: function(){
            return function(){
                return ev.verify(data);
            }
        }
    },
    'scrypt': {
        //Uncomment diff if you want to use hardcoded truncated diff
        //diff: '0000ffff00000000000000000000000000000000000000000000000000000000',
        multiplier: Math.pow(2, 16),
        hash: function(coinConfig){
            var nValue = coinConfig.nValue || 1024;
            var rValue = coinConfig.rValue || 1;
            return function(data){
                return multiHashing.scrypt(data,nValue,rValue);
            }
        }
    },
    'scrypt-og': {
        //Aiden settings
        //Uncomment diff if you want to use hardcoded truncated diff
        //diff: '0000ffff00000000000000000000000000000000000000000000000000000000',
        multiplier: Math.pow(2, 16),
        hash: function(coinConfig){
            var nValue = coinConfig.nValue || 64;
            var rValue = coinConfig.rValue || 1;
            return function(data){
                return multiHashing.scrypt(data,nValue,rValue);
            }
        }
    },
    'scrypt-jane': {
        multiplier: Math.pow(2, 16),
        hash: function(coinConfig){
            var nTimestamp = coinConfig.chainStartTime || 1367991200;
            var nMin = coinConfig.nMin || 4;
            var nMax = coinConfig.nMax || 30;
            return function(data, nTime){
                return multiHashing.scryptjane(data, nTime, nTimestamp, nMin, nMax);
            }
        }
    },
    'scrypt-n': {
        multiplier: Math.pow(2, 16),
        hash: function(coinConfig){

            var timeTable = coinConfig.timeTable || {
                "2048": 1389306217, "4096": 1456415081, "8192": 1506746729, "16384": 1557078377, "32768": 1657741673,
                "65536": 1859068265, "131072": 2060394857, "262144": 1722307603, "524288": 1769642992
            };

            var nFactor = (function(){
                var n = Object.keys(timeTable).sort().reverse().filter(function(nKey){
                    return Date.now() / 1000 > timeTable[nKey];
                })[0];

                var nInt = parseInt(n);
                return Math.log(nInt) / Math.log(2);
            })();

            return function(data) {
                return multiHashing.scryptn(data, nFactor);
            }
        }
    },
    yescrypt: {
        multiplier: Math.pow(2, 16),
        hash: function(){
            return function(data){
                return multiHashing.yescrypt(data);
            }
        }
    },
    yescryptR16: {
        multiplier: Math.pow(2, 16),
        hash: function(){
            return function(data){
                return multiHashing.yescryptR16(data);
            }
        }
    },
    yescryptR32: {
        multiplier: Math.pow(2, 16),
        hash: function(){
            return function(data){
                return multiHashing.yescryptR32(data);
            }
        }
    },
    'neoscrypt': {
        multiplier: Math.pow(2, 16),
        hash: function(coinConfig){
            var nValue = coinConfig.nValue || 1024;
            var rValue = coinConfig.rValue || 1;
            return function(data){
                return multiHashing.neoscrypt(data,nValue,rValue);
            }
        }
    },
    blake2b: {
        hash: function(){
            return function(data){
                return multiHashing.blake2b(data);
            }
        }
    },
    blake2s: {
        hash: function(){
            return function(){
                return multiHashing.blake2s(data);
            }
        }
    },
    cryptonight: {
        hash: function () {
            return function (data) {
                return multiHashing.cryptoNight(data, false);
            }
        }
    },
    sha1: {
        hash: function(){
            return function(){
                return multiHashing.sha1(data);
            }
        }
    },
    x11: {
        hash: function(){
            return function(){
                return multiHashing.x11(data);
            }
        }
    },
    x13: {
        hash: function(){
            return function(){
                return multiHashing.x13(data);
            }
        }
    },
    x15: {
        hash: function(){
            return function(){
                return multiHashing.x15(data);
            }
        }
    },
    nist5: {
        hash: function(){
            return function(){
                return multiHashing.nist5(data);
            }
        }
    },
    quark: {
        hash: function(){
            return function(){
                return multiHashing.quark(data);
            }
        }
    },
    keccak: {
        multiplier: Math.pow(2, 8),
        hash: function(coinConfig){
            if (coinConfig.normalHashing === true) {
                return function (data, nTimeInt) {
                    return multiHashing.keccak(multiHashing.keccak(Buffer.concat([data, new Buffer(nTimeInt.toString(16), 'hex')])));
                };
            }
            else {
                return function () {
                    return multiHashing.keccak(data);
                }
            }
        }
    },
    blake: {
        multiplier: Math.pow(2, 8),
        hash: function(){
            return function(){
                return multiHashing.blake(data);
            }
        }
    },
    skein: {
        hash: function(){
            return function(){
                return multiHashing.skein(data);
            }
        }
    },
    groestl: {
        multiplier: Math.pow(2, 8),
        hash: function(){
            return function(){
                return multiHashing.groestl(data);
            }
        }
    },
    fugue: {
        multiplier: Math.pow(2, 8),
        hash: function(){
            return function(){
                return multiHashing.fugue(data);
            }
        }
    },
    shavite3: {
        hash: function(){
            return function(){
                return multiHashing.shavite3(data);
            }
        }
    },
    hefty1: {
        hash: function(){
            return function(){
                return multiHashing.hefty1(data);
            }
        }
    },
    xevan: {
        hash: function(){
            return function(){
                return multiHashing.xevan(data);
            }
        }
    },
    qubit: {
        hash: function(){
            return function(){
                return multiHashing.qubit(data);
            }
        }
    }
};


for (var algo in algos){
    if (!algos[algo].multiplier)
        algos[algo].multiplier = 1;

    /*if (algos[algo].diff){
        algos[algo].maxDiff = bignum(algos[algo].diff, 16);
    }
    else if (algos[algo].shift){
        algos[algo].nonTruncatedDiff = util.shiftMax256Right(algos[algo].shift);
        algos[algo].bits = util.bufferToCompactBits(algos[algo].nonTruncatedDiff);
        algos[algo].maxDiff = bignum.fromBuffer(util.convertBitsToBuff(algos[algo].bits));
    }
    else if (algos[algo].multiplier){
        algos[algo].maxDiff = diff1.mul(Math.pow(2, 32) / algos[algo].multiplier);
    }
    else{
        algos[algo].maxDiff = diff1;
    }*/
}
