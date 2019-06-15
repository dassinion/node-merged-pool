var util = require('./util.js');

/*
This function creates the generation transaction that accepts the reward for
successfully mining a new block.
For some (probably outdated and incorrect) documentation about whats kinda going on here,
see: https://en.bitcoin.it/wiki/Protocol_specification#tx
 */

var generateOutputTransactions = function(poolRecipient, recipients, rpcData, metaData, symbol, network){

   var reward = rpcData.coinbasevalue;

   if (!reward) {
        var nScript = parseInt(rpcData.coinbasetxn.data.slice(82, 84), 16);
        if (nScript == 253) {
            nScript = parseInt(util.reverseHex(rpcData.coinbasetxn.data.slice(84, 84 + 4)), 16);
            nScript = nScript + 2;
        } else if (nScript == 254) {
            nScript = parseInt(util.reverseHex(rpcData.coinbasetxn.data.slice(84, 84 + 8)), 16);
            nScript = nScript + 4;
        } else if (nScript == 255) {
            nScript = parseInt(util.reverseHex(rpcData.coinbasetxn.data.slice(84, 84 + 16)), 16);
            nScript = nScript + 8;
        }
        var posReward = 94 + nScript*2;
        reward = parseInt(util.reverseHex(rpcData.coinbasetxn.data.slice(posReward, posReward + 16)), 16);
        //console.log("reward from coinbasetxn.data => " + reward);
    }

    var rewardToPool = reward;

    var txOutputBuffers = [];


    /* Dash 12.1 */
    if (rpcData.masternode && rpcData.superblock) {
        if (rpcData.masternode.payee) {
            var payeeReward = 0;

            payeeReward = rpcData.masternode.amount;
            reward -= payeeReward;
            rewardToPool -= payeeReward;

            var payeeScript = util.addressToScript(rpcData.masternode.payee);
            txOutputBuffers.push(Buffer.concat([
                util.packInt64LE(payeeReward),
                util.varIntBuffer(payeeScript.length),
                payeeScript
            ]));
        } else if (rpcData.superblock.length > 0) {
            for(var i in rpcData.superblock){
                var payeeReward = 0;

                payeeReward = rpcData.superblock[i].amount;
                reward -= payeeReward;
                rewardToPool -= payeeReward;

                var payeeScript = util.addressToScript(rpcData.superblock[i].payee);
                txOutputBuffers.push(Buffer.concat([
                    util.packInt64LE(payeeReward),
                    util.varIntBuffer(payeeScript.length),
                    payeeScript
                ]));
            }
        }
    }

    if (rpcData.payee) {
	var payeeReward = 0;

        if (rpcData.payee_amount) {
            payeeReward = rpcData.payee_amount;
        } else {
            payeeReward = Math.ceil(reward / 5);
        }

        reward -= payeeReward;
        rewardToPool -= payeeReward;

	if (symbol==="KOTO") {
            var payeeScript = util.zaddressToScript(network, rpcData.payee);
	} else {
            var payeeScript = util.addressToScript(rpcData.payee);
	}
        txOutputBuffers.push(Buffer.concat([
            util.packInt64LE(payeeReward),
            util.varIntBuffer(payeeScript.length),
            payeeScript
        ]));
    }



    for (var i = 0; i < recipients.length; i++){
	if (symbol === "LINX") {
	    var recipientReward = Math.floor(recipients[i].percent * 100000000);
	} else {
            var recipientReward = Math.floor(recipients[i].percent * reward);
	}
        rewardToPool -= recipientReward;

        txOutputBuffers.push(Buffer.concat([
            util.packInt64LE(recipientReward),
            util.varIntBuffer(recipients[i].script.length),
            recipients[i].script
        ]));
    }

    metaData.rewardToPool = rewardToPool;

    txOutputBuffers.unshift(Buffer.concat([
        util.packInt64LE(rewardToPool),
        util.varIntBuffer(poolRecipient.length),
        poolRecipient
    ]));

    if (rpcData.default_witness_commitment !== undefined){
        witness_commitment = new Buffer(rpcData.default_witness_commitment, 'hex');
        txOutputBuffers.unshift(Buffer.concat([
            util.packInt64LE(0),
            util.varIntBuffer(witness_commitment.length),
            witness_commitment
        ]));
    }

/*	    //console.log("checking for pow2_aux1");
    if (rpcData.pow2_aux1 !== undefined && rpcData.pow2_aux1 !== ""){
//        console.log("appending pow2_aux1");
        pow2_commitment = new Buffer(rpcData.pow2_aux1, 'hex');
        txOutputBuffers.push(pow2_commitment);
    }

     //console.log("checking for pow2_aux2");
    if (rpcData.pow2_aux2 !== undefined && rpcData.pow2_aux2 !== ""){
//      console.log("appending for pow2_aux1");
        pow2_reward = new Buffer(rpcData.pow2_aux2, 'hex');
        txOutputBuffers.push(pow2_reward);
    }
*/
    return Buffer.concat([
        util.varIntBuffer(txOutputBuffers.length),
        Buffer.concat(txOutputBuffers)
    ]);

};


exports.CreateGeneration = function(rpcData, publicKey, extraNoncePlaceholder, reward, txMessages, recipients, auxMerkleTree, metaData, symbol){

    var txInputsCount = 1;
    var txOutputsCount = 1;
    var txVersion = txMessages === true ? 2 : 1;
    var txLockTime = 0;

//    var txInPrevOutHash = new Buffer("0000000000000000000000000000000000000000000000000000000000000000", "hex");
    var txInPrevOutHash = 0;
    var txInPrevOutIndex = Math.pow(2, 32) - 1;
    var txInSequence = 0;

    //Only required for POS coins
    var txTimestamp = reward === 'POS' ?
        util.packUInt32LE(rpcData.curtime) : new Buffer([]);

    //For coins that support/require transaction comments
    var txComment = txMessages === true ?
        util.serializeString('https://multipool.coinpool.ml/') :
        new Buffer([]);


    var scriptSigPart1 = Buffer.concat([
        util.serializeNumber(rpcData.height),
        //new Buffer(rpcData.coinbaseaux.flags, 'hex'),
        util.serializeNumber(Date.now() / 1000 | 0),
        new Buffer([extraNoncePlaceholder.length]),
//        new Buffer('fabe6d6d', 'hex'),
//        util.reverseBuffer(auxMerkleTree.root),
//        util.packUInt32LE(auxMerkleTree.data.length),
//        util.packUInt32LE(0)
    ]);

    var scriptSigPart2 = util.serializeString('/nodeStratum/');

    var p1 = Buffer.concat([
        util.packUInt32LE(txVersion),
        txTimestamp,

        //transaction input
        util.varIntBuffer(txInputsCount),
        util.uint256BufferFromHash(txInPrevOutHash),
        util.packUInt32LE(txInPrevOutIndex),
        util.varIntBuffer(scriptSigPart1.length + extraNoncePlaceholder.length + scriptSigPart2.length),
        scriptSigPart1
    ]);


    /*
    The generation transaction must be split at the extranonce (which located in the transaction input
    scriptSig). Miners send us unique extranonces that we use to join the two parts in attempt to create
    a valid share and/or block.
     */


    var outputTransactions = generateOutputTransactions(publicKey, recipients, rpcData, metaData, symbol);

    var p2 = Buffer.concat([
        scriptSigPart2,
        util.packUInt32LE(txInSequence),
        //end transaction input

        //transaction output
        outputTransactions,
        //end transaction ouput

        util.packUInt32LE(txLockTime),
        txComment
    ]);

    return [p1, p2];
};
