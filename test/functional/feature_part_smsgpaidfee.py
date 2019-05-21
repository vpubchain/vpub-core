#!/usr/bin/env python3
# Copyright (c) 2017-2019 The Vpub Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import struct

from test_framework.test_vpub import ParticlTestFramework
from test_framework.util import connect_nodes


def getvarint(bb, ofs=0):
    i = bb[ofs] & 0x7F
    nb = 1
    ofs += 1
    while (bb[ofs-1] & 0x80):
        i += (bb[ofs] & 0x7F) << (7 * nb)
        ofs += 1
        nb += 1
    return i, nb


def putvarint(i):
    bb = bytearray()
    b = i & 0x7F
    i = i >> 7
    while i > 0:
        bb += bytes([b | 0x80,])
        b = i & 0x7F
        i = i >> 7
    bb += bytes([b,])
    return bb


class SmsgPaidFeeTest(ParticlTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [['-debug', '-nocheckblockindex', '-noacceptnonstdtxn', '-reservebalance=10000000'] for i in range(self.num_nodes)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self, split=False):
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()
        connect_nodes(self.nodes[0], 1)

        self.sync_all()

    def run_test (self):
        tmpdir = self.options.tmpdir
        nodes = self.nodes

        nodes[0].extkeyimportmaster('abandon baby cabbage dad eager fabric gadget habit ice kangaroo lab absorb')
        assert(nodes[0].getwalletinfo()['total_balance'] == 100000)

        nodes[1].extkeyimportmaster('pact mammal barrel matrix local final lecture chunk wasp survey bid various book strong spread fall ozone daring like topple door fatigue limb olympic', '', 'true')
        nodes[1].getnewextaddress('lblExtTest')
        nodes[1].rescanblockchain()
        assert(nodes[1].getwalletinfo()['total_balance'] == 25000)

        assert(nodes[0].smsggetfeerate() == 50000)

        self.stakeBlocks(1, fSync=False)

        ro = nodes[0].getblock(nodes[0].getblockhash(1), 2)
        assert(float(ro['tx'][0]['vout'][0]['smsgfeerate']) == 0.0005)

        ro = nodes[0].walletsettings('stakingoptions', {'smsgfeeratetarget' : 0.001})
        assert(float(ro['stakingoptions']['smsgfeeratetarget']) == 0.001)

        blk1_hex = nodes[0].getblock(nodes[0].getblockhash(1), 0)
        ro = nodes[2].submitblock(blk1_hex)
        assert(ro is None)

        self.stakeBlocks(1, fSync=False)

        ro = nodes[0].getblock(nodes[0].getblockhash(2), 2)
        stakedaddress = ro['tx'][0]['vout'][1]['scriptPubKey']['addresses'][0]
        coinstaketx = ro['tx'][0]['hex']
        assert(float(ro['tx'][0]['vout'][0]['smsgfeerate']) == 0.00050215)
        blk2_hex = nodes[0].getblock(nodes[0].getblockhash(2), 0)

        assert(nodes[0].getblockchaininfo()['blocks'] == 2)

        nodes[0].rewindchain(1)
        nodes[1].rewindchain(1)

        ro = nodes[0].getblockchaininfo()
        assert(ro['blocks'] == 1)

        txb = bytearray.fromhex(coinstaketx)
        assert(txb[0] == 0xa0)  # tx version
        assert(txb[1] == 0x02)  # tx type (coinstake)
        assert(txb[6] == 0x01)  # nInputs
        assert(txb[43] == 0x00)  # scriptSig
        assert(txb[48] == 0x03)  # num outputs
        assert(txb[49] == 0x04)  # OUTPUT_DATA
        assert(txb[50] == 0x08)  # length of data vector
        block_height = struct.unpack('<i', txb[51:55])[0]
        assert(block_height == 2)

        assert(txb[55] == 0x09)  # DO_SMSG
        i, nb = getvarint(txb, 56)
        assert(i == 50215)

        varint_bb = txb[56:56 + nb]
        varint = putvarint(50215)
        assert(varint_bb == varint)

        txb[50] -= nb + 1
        txb = txb[:55] + txb[55 + nb + 1:]


        ro = nodes[0].decoderawtransaction(txb.hex())
        assert(len(ro['vout'][0]['data_hex']) == 8)

        ro = nodes[0].signrawtransactionwithwallet(txb.hex())
        block_hex = self.nodes[0].rehashblock(blk2_hex, stakedaddress, [{'txn': ro['hex'], 'pos': 0, 'replace': True}])
        assert('bad-cs-smsg-fee' == nodes[2].submitblock(block_hex))


        self.log.info('Increase too large')
        varint = putvarint(50216)
        txb[50] += len(varint) + 1
        txb = txb[:55] + bytes([0x09, ]) + varint + txb[55:]

        ro = nodes[0].signrawtransactionwithwallet(txb.hex())
        block_hex = self.nodes[0].rehashblock(blk2_hex, stakedaddress, [{'txn': ro['hex'], 'pos': 0, 'replace': True}])
        assert('bad-cs-smsg-fee' == nodes[2].submitblock(block_hex))


        self.log.info('Decrease too large')
        varint = putvarint(49784)
        txb[50] += len(varint) + 1
        txb = txb[:55] + bytes([0x09, ]) + varint + txb[55:]

        ro = nodes[0].signrawtransactionwithwallet(txb.hex())
        block_hex = self.nodes[0].rehashblock(blk2_hex, stakedaddress, [{'txn': ro['hex'], 'pos': 0, 'replace': True}])
        assert('bad-cs-smsg-fee' == nodes[2].submitblock(block_hex))

        # Should verify
        varint = putvarint(49785)
        txb[50] += len(varint) + 1
        txb = txb[:55] + bytes([0x09, ]) + varint + txb[55:]

        ro = nodes[0].signrawtransactionwithwallet(txb.hex())
        block_hex = self.nodes[0].rehashblock(blk2_hex, '', [{'txn': ro['hex'], 'pos': 0, 'replace': True}])
        assert('bad-block-signature' == nodes[0].submitblock(block_hex))

        block_hex = self.nodes[0].rehashblock(block_hex, stakedaddress)
        assert(nodes[2].submitblock(block_hex) is None)

        ro = nodes[2].getblockchaininfo()
        assert(ro['blocks'] == 2)


if __name__ == '__main__':
    SmsgPaidFeeTest().main()
