// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/merkle.h>
#include <tinyformat.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <util/moneystr.h>
#include <versionbitsinfo.h>

#include <chainparamsimport.h>

#include <assert.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

int64_t CChainParams::GetCoinYearReward(int64_t nTime) const
{
    static const int64_t nSecondsInYear = 365 * 24 * 60 * 60;

    if (strNetworkID != "regtest") {
        // Y1 5%, Y2 4%, Y3 3%, Y4 2%, ... YN 2%
        int64_t nYearsSinceGenesis = (nTime - genesis.nTime) / nSecondsInYear;

        if (nYearsSinceGenesis >= 0 && nYearsSinceGenesis < 3) {
            return (5 - nYearsSinceGenesis) * CENT;
        }
    }

    return nCoinYearReward;
};

int64_t CChainParams::GetProofOfStakeReward(const CBlockIndex *pindexPrev, int64_t nFees) const
{
    int64_t nSubsidy;
    // 1~1440 block reward =0 : lkz 2019-5-11
    if (pindexPrev->nHeight >= 0 && pindexPrev->nHeight < 1440){
        nSubsidy = 0 ;
    } else {
       nSubsidy = (pindexPrev->nMoneySupply / COIN) * GetCoinYearReward(pindexPrev->nTime) / (365 * 24 * (60 * 60 / nTargetSpacing));
    }
    
    // nSubsidy = (pindexPrev->nMoneySupply / COIN) * GetCoinYearReward(pindexPrev->nTime) / (365 * 24 * (60 * 60 / nTargetSpacing));
    return nSubsidy + nFees;
};

int64_t CChainParams::GetMaxSmsgFeeRateDelta(int64_t smsg_fee_prev) const
{
     return (smsg_fee_prev * consensus.smsg_fee_max_delta_percent) / 1000000;
};

bool CChainParams::CheckImportCoinbase(int nHeight, uint256 &hash) const
{
    for (auto &cth : Params().vImportedCoinbaseTxns) {
        if (cth.nHeight != (uint32_t)nHeight) {
            continue;
        }
        if (hash == cth.hash) {
            return true;
        }
        return error("%s - Hash mismatch at height %d: %s, expect %s.", __func__, nHeight, hash.ToString(), cth.hash.ToString());
    }

    return error("%s - Unknown height.", __func__);
};


const DevFundSettings *CChainParams::GetDevFundSettings(int64_t nTime) const
{
    for (auto i = vDevFundSettings.rbegin(); i != vDevFundSettings.rend(); ++i) {
        if (nTime > i->first) {
            return &i->second;
        }
    }

    return nullptr;
};

bool CChainParams::IsBech32Prefix(const std::vector<unsigned char> &vchPrefixIn) const
{
    for (auto &hrp : bech32Prefixes)  {
        if (vchPrefixIn == hrp) {
            return true;
        }
    }

    return false;
};

bool CChainParams::IsBech32Prefix(const std::vector<unsigned char> &vchPrefixIn, CChainParams::Base58Type &rtype) const
{
    for (size_t k = 0; k < MAX_BASE58_TYPES; ++k) {
        auto &hrp = bech32Prefixes[k];
        if (vchPrefixIn == hrp) {
            rtype = static_cast<CChainParams::Base58Type>(k);
            return true;
        }
    }

    return false;
};

bool CChainParams::IsBech32Prefix(const char *ps, size_t slen, CChainParams::Base58Type &rtype) const
{
    for (size_t k = 0; k < MAX_BASE58_TYPES; ++k) {
        const auto &hrp = bech32Prefixes[k];
        size_t hrplen = hrp.size();
        if (hrplen > 0
            && slen > hrplen
            && strncmp(ps, (const char*)&hrp[0], hrplen) == 0) {
            rtype = static_cast<CChainParams::Base58Type>(k);
            return true;
        }
    }

    return false;
};

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

const std::pair<const char*, CAmount> regTestOutputs[] = {
    std::make_pair("afe7c881db847cd23db8444769d900d8677d7e1b", 10000 * COIN),
    std::make_pair("b77eeb6b23695314bacd1897edf7b08c6570d0cd", 10000 * COIN),
    std::make_pair("7811f9c09f63700d15462243a32b13e5ac54287", 10000 * COIN),
    std::make_pair("65c3e5f22f3984ec4967f35f895c288fcaf95c31", 10000 * COIN),

    std::make_pair("4764b46a4d06feae1a7029161df54413fb8a9daf", 5000 * COIN),
    std::make_pair("7a5256b27cce221deec4aafcee866d1e2282d96", 5000 * COIN),
    std::make_pair("eb528574c134b053eb4cbc2e19a4825dc24e656a", 5000 * COIN),
    std::make_pair("68e28519bff057f63819abe6b90050d1b17adddb", 5000 * COIN),
};
const size_t nGenesisOutputsRegtest = sizeof(regTestOutputs) / sizeof(regTestOutputs[0]);

const std::pair<const char*, CAmount> genesisOutputs[] = {       
    //wallet-1
    std::make_pair("65c4a17e0bf327e48ecbf27c71364469c771288d",10000    * COIN),
    std::make_pair("45037fa2cd48bbcb2bf3f7162e0b98a414e3a07c",10000    * COIN),
    std::make_pair("ac9dd4989639205b58877abccb72b2444dda0ce2",10000    * COIN),
    std::make_pair("91935e6a721cd13f70421561ed72c7799da815e8",10000    * COIN),
    std::make_pair("f996659f7b18f28096b2a9131883151dce3efe47",10000    * COIN),
    
    std::make_pair("626d64ed4a15bc707c8be1ec594ec4e40090f8d3",10000    * COIN),
    std::make_pair("2c995fdfa9acb9f041853283a87c3b060b6695d1",10000    * COIN),
    std::make_pair("4c5d2193c3542234c03668a4683ac8227a753795",10000    * COIN),
    std::make_pair("3d54258eccfdf4d307d502ba47049ab7ce3e19f9",10000    * COIN),
    std::make_pair("b34a9152197e6728511e3ddf33ffb63232a19ace",10000    * COIN),
    //wallet-2
    std::make_pair("91dc3d7313bd110c962746cf9374f42f4c593cd9",10000    * COIN),
    std::make_pair("e89bba31c6f03a14dedd22d93647b828ad37a790",10000    * COIN),
    std::make_pair("2f08154b5d9c3f814178f9a958c9d730d4d6a390",10000    * COIN),
    std::make_pair("290aa9f29385849a44b5276d2af7572dfc4dd788",10000    * COIN),
    std::make_pair("1ddad8b38f6314b0e191a698f32e439211430b66",10000    * COIN),
    
    std::make_pair("ba77337dceb08ace1f1bc2452f5df7690204c3d8",10000    * COIN),
    std::make_pair("e1bad841bf14bf2d5b6561511986c10b0c38a3c6",10000    * COIN),
    std::make_pair("3dc8ec6b6f270276b9566c47577c989951d97322",10000    * COIN),
    std::make_pair("26a963b19784482f45b6795701a77ac7493e6bfc",10000    * COIN),
    std::make_pair("f5adeb2820318d223955d50d692894762a0459e5",10000    * COIN),
    //wallet-3   
    std::make_pair("f0663080bb673560fb78199fc0fa732aa74754db",20000     * COIN),
    std::make_pair("5b512dccd6858fc1a0845de216522a50567c163f",20000     * COIN),
    std::make_pair("e1a5715e0be236c5b052e3188c2842d167b9cf18",20000     * COIN),
    std::make_pair("2cd9bcad9e4b6c0bef737c85b552fa06f6564225",20000     * COIN),
    std::make_pair("00915d8f4b0f7ed31101bb88adeeeb75c9fb91e0",20000     * COIN),
    //wallet-4
    std::make_pair("2c350727f4458d6bad11ca6b99716264ed6c8c7f",20000     * COIN),
    std::make_pair("fc9c4cca50187eb9425db933502ee10b1a438ad4",20000     * COIN),
    std::make_pair("6ce1d2d3b911342f6b1f4dd997d1f2a42a487aff",20000     * COIN),
    std::make_pair("e472eabab3410cc2613fac084c539c9ba609b611",20000     * COIN),
    std::make_pair("f1354874f4b2953f631d881e0476ebfff5287d08",20000     * COIN),
    //wallet-5
    std::make_pair("efcc93c50e9d3a6312593c5a87715c82e008d99f",20000     * COIN),
    std::make_pair("966900fe5514aaf814007bf850fd080ebf7ae4ad",20000     * COIN),
    std::make_pair("bcb4baf8d9a68a648305a91d0894632072671f25",20000     * COIN),
    std::make_pair("b991c7d774c0a4f23b806643ea7c2b4672d9b113",20000     * COIN),
    std::make_pair("fc12c9e679f9e9ef3ee0a17847422e021316dd39",20000     * COIN),
    //wallet-6
    std::make_pair("c5b9590ec3adaf352c662515dd0f91c59497777f",20000     * COIN),
    std::make_pair("8a4f1f5c5881ba57f0cd7b138bd76d7729d31fe1",20000     * COIN),
    std::make_pair("4973628b3ad42522291f2cf0ad644450c7ccc65c",20000     * COIN),
    std::make_pair("7efb083ca44865e596a2419ec57fec46b307d98b",20000     * COIN),
    std::make_pair("1e19e7d6deee72cc9d9e3de9de5960f1f1782253",20000     * COIN),
    //wallet-7
    std::make_pair("0ef4d981b631a96e70fd3cadab529935f34d6cfb",20000     * COIN),
    std::make_pair("5dbdc37227e0b464c308c218fe5be617c5ca5578",20000     * COIN),
    std::make_pair("ae5655848d3a37abf51d7733379fd7d98c501932",20000     * COIN),
    std::make_pair("62852e18b1de9fc9aee2c726ad235c79b619ec34",20000     * COIN),
    std::make_pair("88205fcf7697897870c8bf30f1859ff1cb585610",20000     * COIN),
    //wallet-8
    std::make_pair("4d49ad3b9ca241e45c605e6a26bfcd621b98c81d",20000     * COIN),
    std::make_pair("f0e06542a404c80a7a5efd31adc94a9a41004daa",20000     * COIN),
    std::make_pair("9b074f26e43a80b991f49bca97e846b2736538cb",20000     * COIN),
    std::make_pair("5b1521d91060c8c503c48e11617a5422216050fa",20000     * COIN),
    std::make_pair("012e4fb888ad0a2b936c4e61ee262aa9fc57a7f1",20000     * COIN),
    //wallet-9
    std::make_pair("9c33394ac8c49b38824f8e89f21e0bb246d24576",20000     * COIN),
    std::make_pair("0cfde8af35af678ac2b099565f26406af3aed4e7",20000     * COIN),
    std::make_pair("c40ca3ed38ef2d29fa6048180603e36233e1d71d",20000     * COIN),
    std::make_pair("87623928e6f7b39052a59d0156b5d48cceee74a5",20000     * COIN),
    std::make_pair("9197004da098dbda8163b7dc69f509303ce63948",20000     * COIN),
    //wallet-10
    std::make_pair("036164a58c79d25fa35381648e42cb90e298ced7",20000     * COIN),
    std::make_pair("e1e8107c5534267261701c529513d3565575eb6c",20000     * COIN),
    std::make_pair("a6716e37da5cb7003dd37c8e44410c4fbd7c0d08",20000     * COIN),
    std::make_pair("6d12f1913ef21231d7786e61452c869ae170a866",20000     * COIN),
    std::make_pair("b26985c561b799ca8aa4cb087dc94184d2ca06e2",20000     * COIN),
};
const size_t nGenesisOutputs = sizeof(genesisOutputs) / sizeof(genesisOutputs[0]);

const std::pair<const char*, CAmount> genesisOutputsTestnet[] = {
    std::make_pair("da708d4837449773b2b992bcf632c3e5ede4b816",200000    * COIN),
    std::make_pair("33626525f092614ffeba7184f59d377233606512",200000    * COIN),
    std::make_pair("bff5c2122f1b15e81813264ef682f162e06570fc",200000    * COIN),
    std::make_pair("81cf20dc7588356340f9cb9350a75454db2be90e",200000    * COIN),
    std::make_pair("b018a97c518613f7075bb23809c20fb891097e2c",200000    * COIN),

    std::make_pair("69345d6be457b994627cf9ad5190c91459977f60",200000    * COIN),
    std::make_pair("6376a3489d220a0db00c0d734c73ab167558d07f",200000    * COIN),
    std::make_pair("05eb66e0d695a632900934942ab77643a9c5f660",200000     * COIN),
    std::make_pair("04a6eb77602392ed79958be78ef9632f82cb124a",200000    * COIN),
    std::make_pair("c43453cf155302598e3d15476664eb7e0d4e67c6",200000     * COIN),
    
};
const size_t nGenesisOutputsTestnet = sizeof(genesisOutputsTestnet) / sizeof(genesisOutputsTestnet[0]);


static CBlock CreateGenesisBlockRegTest(uint32_t nTime, uint32_t nNonce, uint32_t nBits)
{
    const char *pszTimestamp = "The Times 16:00:02 17/04/2019 created by jiuling vpubchain";

    CMutableTransaction txNew;
    txNew.nVersion = VPUB_TXN_VERSION;
    txNew.SetType(TXN_COINBASE);
    txNew.vin.resize(1);
    uint32_t nHeight = 0;  // bip34
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp)) << OP_RETURN << nHeight;

    txNew.vpout.resize(nGenesisOutputsRegtest);
    for (size_t k = 0; k < nGenesisOutputsRegtest; ++k) {
        OUTPUT_PTR<CTxOutStandard> out = MAKE_OUTPUT<CTxOutStandard>();
        out->nValue = regTestOutputs[k].second;
        out->scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ParseHex(regTestOutputs[k].first) << OP_EQUALVERIFY << OP_CHECKSIG;
        txNew.vpout[k] = out;
    }

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = VPUB_BLOCK_VERSION;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));

    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    genesis.hashWitnessMerkleRoot = BlockWitnessMerkleRoot(genesis);

    return genesis;
}

static CBlock CreateGenesisBlockTestNet(uint32_t nTime, uint32_t nNonce, uint32_t nBits)
{
    const char *pszTimestamp = "The Times 14:00:00 14/05/2019 created by jiuling vpubchain";

    CMutableTransaction txNew;
    txNew.nVersion = VPUB_TXN_VERSION;
    txNew.SetType(TXN_COINBASE);
    txNew.vin.resize(1);
    uint32_t nHeight = 0;  // bip34
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp)) << OP_RETURN << nHeight;

    txNew.vpout.resize(nGenesisOutputsTestnet);
    for (size_t k = 0; k < nGenesisOutputsTestnet; ++k) {
        OUTPUT_PTR<CTxOutStandard> out = MAKE_OUTPUT<CTxOutStandard>();
        out->nValue = genesisOutputsTestnet[k].second;
        out->scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ParseHex(genesisOutputsTestnet[k].first) << OP_EQUALVERIFY << OP_CHECKSIG;
        txNew.vpout[k] = out;
    }

    // rANYFdZUwWGgqsGLsuaSZGoeFURctXXGSD
    OUTPUT_PTR<CTxOutStandard> out = MAKE_OUTPUT<CTxOutStandard>();
    out = MAKE_OUTPUT<CTxOutStandard>();
    out->nValue = 150000 * COIN;
    out->scriptPubKey = CScript() << OP_HASH160 << ParseHex("b0d8020986e7d6c4873295ecaf6d53d00136253d") << OP_EQUAL;
    txNew.vpout.push_back(out);

    // Community Initative 2 
    // rPPwm4YWWxY7PKxpE6EBFCj4piskKQRxZX
    out = MAKE_OUTPUT<CTxOutStandard>();
    out->nValue = 200000 * COIN;
    out->scriptPubKey = CScript() << OP_HASH160 << ParseHex("df842dce26c76df7fee7a39f471858779b7ea871") << OP_EQUAL;
    txNew.vpout.push_back(out);
    
    // Reserved vpubchain
    // rQvHcgyrwFgKMnjnr147Mk72zUL71D8qre
    out = MAKE_OUTPUT<CTxOutStandard>();
    out->nValue = 1000000 * COIN;
    out->scriptPubKey = CScript() << OP_HASH160 << ParseHex("ea4d7e3d7fd2ad3f569a21b62d19dbd4b2bb1c3d") << OP_EQUAL;
    txNew.vpout.push_back(out);

    // Reserved vpubchain for primary round
    // rDDoim2PGunVmhWCuDMytGAp5RtbcyqPGN
    out = MAKE_OUTPUT<CTxOutStandard>();
    out->nValue = 1000000 * COIN;
    out->scriptPubKey = CScript() << 1557986400 << OP_CHECKLOCKTIMEVERIFY << OP_DROP << OP_HASH160<< ParseHex("fe96ca68034a74d44bbc46cde9fa2036eb56d45b") << OP_EQUAL; // 2017-11-30
    txNew.vpout.push_back(out);


    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = VPUB_BLOCK_VERSION;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));

    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    genesis.hashWitnessMerkleRoot = BlockWitnessMerkleRoot(genesis);

    return genesis;
}

static CBlock CreateGenesisBlockMainNet(uint32_t nTime, uint32_t nNonce, uint32_t nBits)
{
    const char *pszTimestamp = "China issues 5G licenses today ";

    CMutableTransaction txNew;
    txNew.nVersion = VPUB_TXN_VERSION;
    txNew.SetType(TXN_COINBASE);

    txNew.vin.resize(1);
    uint32_t nHeight = 0;  // bip34
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp)) << OP_RETURN << nHeight;
    txNew.vpout.resize(nGenesisOutputs);
    for (size_t k = 0; k < nGenesisOutputs; ++k) {
        OUTPUT_PTR<CTxOutStandard> out = MAKE_OUTPUT<CTxOutStandard>();
        out->nValue = genesisOutputs[k].second;
        out->scriptPubKey = CScript() << OP_DUP << OP_HASH160 << ParseHex(genesisOutputs[k].first) << OP_EQUALVERIFY << OP_CHECKSIG;
        txNew.vpout[k] = out;
    }

    // Community Initative 1
    // RTHzD2yc9zMepN8Z8EKWUnqjSG15Pr3SPj
    OUTPUT_PTR<CTxOutStandard> out = MAKE_OUTPUT<CTxOutStandard>();
    out = MAKE_OUTPUT<CTxOutStandard>();
    out->nValue = 5000000 * COIN;
    out->scriptPubKey = CScript() << OP_HASH160 << ParseHex("ff8624af288f7a7452c4a35f898f62069038a4cb") << OP_EQUAL;
    txNew.vpout.push_back(out);

    // Community Initative 2 
    // REaKwXE8UzmPB1UkoisCpdXLy6g1YTMZk5
    out = MAKE_OUTPUT<CTxOutStandard>();
    out->nValue = 5000000 * COIN;
    out->scriptPubKey = CScript() << OP_HASH160 << ParseHex("22228654b4a9b6a6249d102bf0b84ee5d05dc3c4") << OP_EQUAL;
    txNew.vpout.push_back(out);

    // Reserved Vpub 
    // RN4MHCjXfzo7a3c1whZt5mbuLd7Bbh9FY3
    out = MAKE_OUTPUT<CTxOutStandard>();
    out->nValue = 5000000 * COIN;
    out->scriptPubKey = CScript() << OP_HASH160 << ParseHex("a88d48f5a09cdfb92f0b9a4130d199b91b102133") << OP_EQUAL;
    txNew.vpout.push_back(out);

    // Reserved Vpub for primary round
    // RVdtjTBEqoFPyxNDqFk72SXkvq19QtKss9
    out = MAKE_OUTPUT<CTxOutStandard>();
    out->nValue = 5000000 * COIN;
    out->scriptPubKey = CScript() << 1557990000 << OP_CHECKLOCKTIMEVERIFY << OP_DROP << OP_HASH160<< ParseHex("92dad3ff9b5938bb7178681ef4492e957baf7585") << OP_EQUAL; // 2017-11-30
    txNew.vpout.push_back(out);


    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = VPUB_BLOCK_VERSION;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));

    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    genesis.hashWitnessMerkleRoot = BlockWitnessMerkleRoot(genesis);

    return genesis;
}


/**
 * Main network
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";

        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP34Height = 0;
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.OpIsCoinstakeTime = 1510272000; // 2017-11-10 00:00:00 UTC
        consensus.fAllowOpIsCoinstakeWithP2PKH = false;
        consensus.nPaidSmsgTime = 0x5C791EC0;       // 2019-03-01 12:00:00
        consensus.csp2shTime = 0x5C791EC0;          // 2019-03-01 12:00:00
        consensus.smsg_fee_time = 0xFFFFFFFF;       // 2106 TODO: lower
        consensus.bulletproof_time = 0xFFFFFFFF;    // 2106 TODO: lower
        consensus.rct_time = 0xFFFFFFFF;            // 2106 TODO: lower

        consensus.smsg_fee_period = 5040;
        consensus.smsg_fee_funding_tx_per_k = 200000;
        consensus.smsg_fee_msg_per_day_per_k = 50000;
        consensus.smsg_fee_max_delta_percent = 43;

        consensus.powLimit = uint256S("000000000000bfffffffffffffffffffffffffffffffffffffffffffffffffff");

        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1462060800; // May 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1479168000; // November 15th, 2016.
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1510704000; // November 15th, 2017.

        // The best chain should have at least this much work.
        //consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000467b28adaecf2f81c8");
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x0000ee0141b0e3537d376a09660ffde7548c11c188518ef4fbca889e90f4dc67"); // 0

        consensus.nMinRCTOutputDepth = 12;

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xfd;
        pchMessageStart[1] = 0xf2;
        pchMessageStart[2] = 0xef;
        pchMessageStart[3] = 0xb4;
        nDefaultPort = 51758;
        nBIP44ID = 0x8000002C;

        nModifierInterval = 10 * 60;    // 10 minutes
        nStakeMinConfirmations = 225;   // 225 * 2 minutes
        nTargetSpacing = 120;           // 2 minutes
        nTargetTimespan = 24 * 60;      // 24 mins

        AddImportHashesMain(vImportedCoinbaseTxns);
        SetLastImportHeight();

        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 1;
        m_assumed_chain_state_size = 1;

        //genesis = CreateGenesisBlockMainNet(1500296400, 31429, 0x1f00ffff); // 2017-07-17 13:00:00
        genesis = CreateGenesisBlockMainNet(1559786400, 16885,  0x1f00ffff); // 2019-06-06 10:00:00
        consensus.hashGenesisBlock = genesis.GetHash();
        
        bool fNegative;
        bool fOverflow;
        arith_uint256 bnTarget;

        uint32_t i;
        uint256 hash;

        bnTarget.SetCompact(genesis.nBits, &fNegative, &fOverflow);
                std::cout << "target:" << bnTarget.GetHex() << std::endl;

                for (i = 0; i < 4294967295; i++) {
                genesis.nNonce=i;
                hash = genesis.GetHash();
                //std::cout << "hash:" << hash.GetHex() << std::endl;
                if (UintToArith256(hash) <= bnTarget){
                        //std::cout << "nonce:" << i << std::endl;
                        break;
                }
        }
        hash = genesis.GetHash();
        if (UintToArith256(hash) <= bnTarget){
                std::cout << "nonce1:" << i << std::endl;
        }
        
        std::cout << "block:" << consensus.hashGenesisBlock.GetHex() << std::endl;
        std::cout << "merkle:" << genesis.hashMerkleRoot.GetHex() << std::endl;
        std::cout << "witness:" << genesis.hashWitnessMerkleRoot.GetHex() << std::endl;
	
        assert(consensus.hashGenesisBlock == uint256S("0x000047a5d383d8ed0698caae75d91b58f7f154223fc0005891291b68c04af775"));
        assert(genesis.hashMerkleRoot == uint256S("0xb351538ab7e88fcb7bec7f5ec07ce809ebfb8ef1b43c463abae8586efaba9e41"));
        assert(genesis.hashWitnessMerkleRoot == uint256S("0xe99194fb12514b08be729eeeba8c4c1b399c4befef378fec7353c51614bde890"));

	    //assert(consensus.hashGenesisBlock == uint256S("0x0000ee0784c195317ac95623e22fddb8c7b8825dc3998e0bb924d66866eccf4c"));
        //assert(genesis.hashMerkleRoot == uint256S("0xc95fb023cf4bc02ddfed1a59e2b2f53edd1a726683209e2780332edf554f1e3e"));
        //assert(genesis.hashWitnessMerkleRoot == uint256S("0x619e94a7f9f04c8a1d018eb8bcd9c42d3c23171ebed8f351872256e36959d66c"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as a oneshot if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        //vSeeds.emplace_back("mainnet-seed.vpub.io");
        //vSeeds.emplace_back("dnsseed-mainnet.vpub.io");
        //vSeeds.emplace_back("mainnet.vpub.io");
        vSeeds.emplace_back("52.82.7.73");


        vDevFundSettings.emplace_back(0,
            DevFundSettings("RPLYxZFbBwBYToQpWavLWAtjpoSgLQQmh4", 10, 60));
        vDevFundSettings.emplace_back(consensus.OpIsCoinstakeTime,
            DevFundSettings("RAJ3GeQ2UsCrqpPSS36pcDPnk2X4Ydi9kS", 10, 60));


        base58Prefixes[PUBKEY_ADDRESS]     = {0x38}; // P
        base58Prefixes[SCRIPT_ADDRESS]     = {0x3c};
        base58Prefixes[PUBKEY_ADDRESS_256] = {0x39};
        base58Prefixes[SCRIPT_ADDRESS_256] = {0x3d};
        base58Prefixes[SECRET_KEY]         = {0x6c};
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x69, 0x6e, 0x82, 0xd1}; // PPAR
        base58Prefixes[EXT_SECRET_KEY]     = {0x8f, 0x1d, 0xae, 0xb8}; // XPAR
        base58Prefixes[STEALTH_ADDRESS]    = {0x14};
        base58Prefixes[EXT_KEY_HASH]       = {0x4b}; // X
        base58Prefixes[EXT_ACC_HASH]       = {0x17}; // A
        base58Prefixes[EXT_PUBLIC_KEY_BTC] = {0x04, 0x88, 0xB2, 0x1E}; // xpub
        base58Prefixes[EXT_SECRET_KEY_BTC] = {0x04, 0x88, 0xAD, 0xE4}; // xprv

        bech32Prefixes[PUBKEY_ADDRESS].assign       ("ph","ph"+2);
        bech32Prefixes[SCRIPT_ADDRESS].assign       ("pr","pr"+2);
        bech32Prefixes[PUBKEY_ADDRESS_256].assign   ("pl","pl"+2);
        bech32Prefixes[SCRIPT_ADDRESS_256].assign   ("pj","pj"+2);
        bech32Prefixes[SECRET_KEY].assign           ("px","px"+2);
        bech32Prefixes[EXT_PUBLIC_KEY].assign       ("pep","pep"+3);
        bech32Prefixes[EXT_SECRET_KEY].assign       ("pex","pex"+3);
        bech32Prefixes[STEALTH_ADDRESS].assign      ("ps","ps"+2);
        bech32Prefixes[EXT_KEY_HASH].assign         ("pek","pek"+3);
        bech32Prefixes[EXT_ACC_HASH].assign         ("pea","pea"+3);
        bech32Prefixes[STAKE_ONLY_PKADDR].assign    ("pcs","pcs"+3);

        bech32_hrp = "bc";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {
                { 0,        uint256S("0x000047a5d383d8ed0698caae75d91b58f7f154223fc0005891291b68c04af775")},
                /*{ 5000,     uint256S("0xe786020ab94bc5461a07d744f3631a811b4ebf424fceda12274f2321883713f4")},
                { 15000,    uint256S("0xafc73ac299f2e6dd309077d230fccef547b9fc24379c1bf324dd3683b13c61c3")},
                { 30000,    uint256S("0x35d95c12799323d7b418fd64df9d88ef67ef27f057d54033b5b2f38a5ecaacbf")},
                { 91000,    uint256S("0x4d1ffaa5b51431918a0c74345e2672035c743511359ac8b1be67467b02ff884c")},
                { 112250,   uint256S("0x89e4b23471aea7a875df835d6f89613fd87ba649e7a1d8cb892917d0080ef337")},
                { 128650,   uint256S("0x43597f7dd16719ab2ea63e9c34266120c85cf592a4ec61f82822003da6874408")},
                { 159010,   uint256S("0xb724d359a10aaa51755a65da830f4aaf4e44aad0246ebf5f73171122bc4b3997")},
                { 170880,   uint256S("0x03d23bd24386ebeb41c81f84145c46cc3f64e4d114b2b8d2bb14e5855f254f2a")},
                { 213800,   uint256S("0xfd6c0e5f7444a9e09a5fa1652db73d5b8628aeabe162529a5356be700509aa80")},
                { 254275,   uint256S("0x7f454ac5629ef667f40f900357d30bd63b7983363255880fd155fadbc9add957")},
                { 282130,   uint256S("0xf720421256795081c1d985e997bb81d040d557f24b9e2d16a1c13d21734fb2b1")},
                { 303640,   uint256S("0x7cc035d7888ee6d824cec8ff01a6287a71873d874f72a5fd3706d227b88f8e99")},
                { 357320,   uint256S("0x20b01f2bef93197bb014d27125939cd8d4f6a34257fdb498ae64c8644b8f2289")},
                { 376100,   uint256S("0xff704cb42547da4efb2b32054c72c7682b7634ac34fda4ec88fe7badc666338c")},*/
            }
        };

        chainTxData = ChainTxData {
            // Data from rpc: getchaintxstats 4096 ff704cb42547da4efb2b32054c72c7682b7634ac34fda4ec88fe7badc666338c
            /* nTime    */ 1559786400,
            /* nTxCount */ 0,
            /* dTxRate  */ 0
        };

        /* disable fallback fee on mainnet */
        m_fallback_fee_enabled = false;
    }

    void SetOld()
    {
        consensus.BIP16Exception = uint256S("0x00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22");
        consensus.BIP34Height = 227931;
        consensus.BIP34Hash = uint256S("0x000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8");
        consensus.BIP65Height = 388381; // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        consensus.BIP66Height = 363725; // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        genesis = CreateGenesisBlock(1231006505, 2083236893, 0x1d00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP34Height = 0;
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.OpIsCoinstakeTime = 0;
        consensus.fAllowOpIsCoinstakeWithP2PKH = true; // TODO: clear for next testnet
        consensus.nPaidSmsgTime = 0;
        consensus.csp2shTime = 0x5C67FB40;          // 2019-02-16 12:00:00
        consensus.smsg_fee_time = 0x5C67FB40;       // 2019-02-16 12:00:00
        consensus.bulletproof_time = 0x5C67FB40;    // 2019-02-16 12:00:00
        consensus.rct_time = 0;

        consensus.smsg_fee_period = 5040;
        consensus.smsg_fee_funding_tx_per_k = 200000;
        consensus.smsg_fee_msg_per_day_per_k = 50000;
        consensus.smsg_fee_max_delta_percent = 43;

        consensus.powLimit = uint256S("000000000005ffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1456790400; // March 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1462060800; // May 1st 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1493596800; // May 1st 2017

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0xd7");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00000523baa77736a9b7e6b8f7a363caa8b05c84a16624801a7f4cdfa72ee98d"); // 0

        consensus.nMinRCTOutputDepth = 12;

        pchMessageStart[0] = 0x0a;
        pchMessageStart[1] = 0x11;
        pchMessageStart[2] = 0x05;
        pchMessageStart[3] = 0x0b;
        nDefaultPort = 51958;
        nBIP44ID = 0x80000001;

        nModifierInterval = 10 * 60;    // 10 minutes
        nStakeMinConfirmations = 225;   // 225 * 2 minutes
        nTargetSpacing = 120;           // 2 minutes
        nTargetTimespan = 24 * 60;      // 24 mins


        AddImportHashesTest(vImportedCoinbaseTxns);
        SetLastImportHeight();

        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 1;
        m_assumed_chain_state_size = 1;

        //genesis = CreateGenesisBlockTestNet(1502309248, 5924, 0x1f00ffff);
        genesis = CreateGenesisBlockTestNet(1557813600, 110534, 0x1f00ffff); //2019-05-14
        consensus.hashGenesisBlock = genesis.GetHash();
	
        bool fNegative;
        bool fOverflow;
        arith_uint256 bnTarget;

        uint32_t i;
        uint256 hash;

        bnTarget.SetCompact(genesis.nBits, &fNegative, &fOverflow);
        std::cout << "target:" << bnTarget.GetHex() << std::endl;

        for (i = 0; i < 4294967295; i++) {
            genesis.nNonce=i;
            hash = genesis.GetHash();
            //std::cout << "hash:" << hash.GetHex() << std::endl;
            if (UintToArith256(hash) <= bnTarget){
                //std::cout << "nonce:" << i << std::endl;
                break;
            }
        }
        hash = genesis.GetHash();
        if (UintToArith256(hash) <= bnTarget){
                std::cout << "nonce1:" << i << std::endl;
        }
	
        std::cout << "block:" << consensus.hashGenesisBlock.GetHex() << std::endl;
        std::cout << "merkle:" << genesis.hashMerkleRoot.GetHex() << std::endl;
        std::cout << "witness:" << genesis.hashWitnessMerkleRoot.GetHex() << std::endl;
 	    
        assert(consensus.hashGenesisBlock == uint256S("0x0000c707156c22cc39e923d763fcab3ae96a9587b74c184759d6e4b198da4e31"));
        assert(genesis.hashMerkleRoot == uint256S("0xa043431b6e581fea56c2170f69470156823a12bf166e6980eedcef7348e16444"));
        assert(genesis.hashWitnessMerkleRoot == uint256S("0xec19be1b45625c1898f4df0b5f551f87c953ef0c013edf770e4dc339e63c0df8"));

        //assert(consensus.hashGenesisBlock == uint256S("0x0000594ada5310b367443ee0afd4fa3d0bbd5850ea4e33cdc7d6a904a7ec7c90"));
        //assert(genesis.hashMerkleRoot == uint256S("0x2c7f4d88345994e3849502061f6303d9666172e4dff3641d3472a72908eec002"));
        //assert(genesis.hashWitnessMerkleRoot == uint256S("0xf9e2235c9531d5a19263ece36e82c4d5b71910d73cd0b677b81c5e50d17b6cda"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        //vSeeds.emplace_back("testnet-seed.vpub.io");
        //vSeeds.emplace_back("dnsseed-testnet.vpub.io");
        vSeeds.emplace_back("47.105.68.82");
        vSeeds.emplace_back("47.105.157.227");

        //vDevFundSettings.push_back(std::make_pair(0, DevFundSettings("rTvv9vsbu269mjYYEecPYinDG8Bt7D86qD", 10, 60)));
        vDevFundSettings.push_back(std::make_pair(0, DevFundSettings("rQApnBUWAmJ28PHzaFw9gPeqiDFBxPWK3B", 10, 100)));

        base58Prefixes[PUBKEY_ADDRESS]     = {0x76}; // p
        base58Prefixes[SCRIPT_ADDRESS]     = {0x7a};
        base58Prefixes[PUBKEY_ADDRESS_256] = {0x77};
        base58Prefixes[SCRIPT_ADDRESS_256] = {0x7b};
        base58Prefixes[SECRET_KEY]         = {0x2e};
        base58Prefixes[EXT_PUBLIC_KEY]     = {0xe1, 0x42, 0x78, 0x00}; // ppar
        base58Prefixes[EXT_SECRET_KEY]     = {0x04, 0x88, 0x94, 0x78}; // xpar
        base58Prefixes[STEALTH_ADDRESS]    = {0x15}; // T
        base58Prefixes[EXT_KEY_HASH]       = {0x89}; // x
        base58Prefixes[EXT_ACC_HASH]       = {0x53}; // a
        base58Prefixes[EXT_PUBLIC_KEY_BTC] = {0x04, 0x35, 0x87, 0xCF}; // tpub
        base58Prefixes[EXT_SECRET_KEY_BTC] = {0x04, 0x35, 0x83, 0x94}; // tprv

        bech32Prefixes[PUBKEY_ADDRESS].assign       ("tph","tph"+3);
        bech32Prefixes[SCRIPT_ADDRESS].assign       ("tpr","tpr"+3);
        bech32Prefixes[PUBKEY_ADDRESS_256].assign   ("tpl","tpl"+3);
        bech32Prefixes[SCRIPT_ADDRESS_256].assign   ("tpj","tpj"+3);
        bech32Prefixes[SECRET_KEY].assign           ("tpx","tpx"+3);
        bech32Prefixes[EXT_PUBLIC_KEY].assign       ("tpep","tpep"+4);
        bech32Prefixes[EXT_SECRET_KEY].assign       ("tpex","tpex"+4);
        bech32Prefixes[STEALTH_ADDRESS].assign      ("tps","tps"+3);
        bech32Prefixes[EXT_KEY_HASH].assign         ("tpek","tpek"+4);
        bech32Prefixes[EXT_ACC_HASH].assign         ("tpea","tpea"+4);
        bech32Prefixes[STAKE_ONLY_PKADDR].assign    ("tpcs","tpcs"+4);

        bech32_hrp = "tb";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {
		{0, uint256S("0x0000c707156c22cc39e923d763fcab3ae96a9587b74c184759d6e4b198da4e31")},
                /*{127620, uint256S("0xe5ab909fc029b253bad300ccf859eb509e03897e7853e8bfdde2710dbf248dd1")},
                {210920, uint256S("0x5534f546c3b5a264ca034703b9694fabf36d749d66e0659eef5f0734479b9802")},
                {259290, uint256S("0x58267bdf935a2e0716cb910d055b8cdaa019089a5f71c3db90765dc7101dc5dc")},
                {312860, uint256S("0xaba2e3b2dcf1970b53b67c869325c5eefd3a107e62518fa4640ddcfadf88760d")},
                {331600, uint256S("0xeecbeafc4b338901e3dfb6eeaefc128ef477dfe1e6f0f96bd63da27caf113ddc")},*/
            }
        };

        chainTxData = ChainTxData{
            // Data from rpc: getchaintxstats 4096 eecbeafc4b338901e3dfb6eeaefc128ef477dfe1e6f0f96bd63da27caf113ddc
            /* nTime    */ 1557813600,
            /* nTxCount */ 0,
            /* dTxRate  */ 0
        };

        /* enable fallback fee on testnet */
        m_fallback_fee_enabled = true;
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    explicit CRegTestParams(const ArgsManager& args) {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP16Exception = uint256();
        consensus.BIP34Height = 500; // BIP34 activated on regtest (Used in functional tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in functional tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in functional tests)
        consensus.OpIsCoinstakeTime = 0;
        consensus.fAllowOpIsCoinstakeWithP2PKH = false;
        consensus.nPaidSmsgTime = 0;
        consensus.csp2shTime = 0;
        consensus.smsg_fee_time = 0;
        consensus.bulletproof_time = 0;
        consensus.rct_time = 0;

        consensus.smsg_fee_period = 50;
        consensus.smsg_fee_funding_tx_per_k = 200000;
        consensus.smsg_fee_msg_per_day_per_k = 50000;
        consensus.smsg_fee_max_delta_percent = 4300;

        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        consensus.nMinRCTOutputDepth = 1;

        pchMessageStart[0] = 0x0b;
        pchMessageStart[1] = 0x12;
        pchMessageStart[2] = 0x06;
        pchMessageStart[3] = 0x0c;
        nDefaultPort = 11958;
        nBIP44ID = 0x80000001;


        nModifierInterval = 2 * 60;     // 2 minutes
        nStakeMinConfirmations = 12;
        nTargetSpacing = 5;             // 5 seconds
        nTargetTimespan = 16 * 60;      // 16 mins
        nStakeTimestampMask = 0;

        SetLastImportHeight();

        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        UpdateVersionBitsParametersFromArgs(args);

        //genesis = CreateGenesisBlockRegTest(1487714923, 0, 0x207fffff);
        genesis = CreateGenesisBlockRegTest(1555488002, 0, 0x207fffff);
        consensus.hashGenesisBlock = genesis.GetHash();
        /*
        std::cout << "block:" << consensus.hashGenesisBlock.GetHex() << std::endl;
        std::cout << "merkle:" << genesis.hashMerkleRoot.GetHex() << std::endl;
        std::cout << "witness:" << genesis.hashWitnessMerkleRoot.GetHex() << std::endl;
        */
        assert(consensus.hashGenesisBlock == uint256S("0xb18c0be1691609a6ff5fa2fe52140a5b4b3363443a910b178e742560ca91c265"));
        assert(genesis.hashMerkleRoot == uint256S("0x2af16a74a4cfa57ae22752b495aff4653a9b24be2a42e843d0ed2602a9224d16"));
        assert(genesis.hashWitnessMerkleRoot == uint256S("0x16dc1d3c33b8405083e0292d408052a015806827d52585bc4b02b8feddba7ee6"));
        
        //assert(consensus.hashGenesisBlock == uint256S("0x6cd174536c0ada5bfa3b8fde16b98ae508fff6586f2ee24cf866867098f25907"));
        //assert(genesis.hashMerkleRoot == uint256S("0xf89653c7208af2c76a3070d436229fb782acbd065bd5810307995b9982423ce7"));
        //assert(genesis.hashWitnessMerkleRoot == uint256S("0x36b66a1aff91f34ab794da710d007777ef5e612a320e1979ac96e5f292399639"));


        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = {
            {
                {0, uint256S("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")},
            }
        };

        base58Prefixes[PUBKEY_ADDRESS]     = {0x76}; // p
        base58Prefixes[SCRIPT_ADDRESS]     = {0x7a};
        base58Prefixes[PUBKEY_ADDRESS_256] = {0x77};
        base58Prefixes[SCRIPT_ADDRESS_256] = {0x7b};
        base58Prefixes[SECRET_KEY]         = {0x2e};
        base58Prefixes[EXT_PUBLIC_KEY]     = {0xe1, 0x42, 0x78, 0x00}; // ppar
        base58Prefixes[EXT_SECRET_KEY]     = {0x04, 0x88, 0x94, 0x78}; // xpar
        base58Prefixes[STEALTH_ADDRESS]    = {0x15}; // T
        base58Prefixes[EXT_KEY_HASH]       = {0x89}; // x
        base58Prefixes[EXT_ACC_HASH]       = {0x53}; // a
        base58Prefixes[EXT_PUBLIC_KEY_BTC] = {0x04, 0x35, 0x87, 0xCF}; // tpub
        base58Prefixes[EXT_SECRET_KEY_BTC] = {0x04, 0x35, 0x83, 0x94}; // tprv

        bech32Prefixes[PUBKEY_ADDRESS].assign       ("tph","tph"+3);
        bech32Prefixes[SCRIPT_ADDRESS].assign       ("tpr","tpr"+3);
        bech32Prefixes[PUBKEY_ADDRESS_256].assign   ("tpl","tpl"+3);
        bech32Prefixes[SCRIPT_ADDRESS_256].assign   ("tpj","tpj"+3);
        bech32Prefixes[SECRET_KEY].assign           ("tpx","tpx"+3);
        bech32Prefixes[EXT_PUBLIC_KEY].assign       ("tpep","tpep"+4);
        bech32Prefixes[EXT_SECRET_KEY].assign       ("tpex","tpex"+4);
        bech32Prefixes[STEALTH_ADDRESS].assign      ("tps","tps"+3);
        bech32Prefixes[EXT_KEY_HASH].assign         ("tpek","tpek"+4);
        bech32Prefixes[EXT_ACC_HASH].assign         ("tpea","tpea"+4);
        bech32Prefixes[STAKE_ONLY_PKADDR].assign    ("tpcs","tpcs"+4);

        bech32_hrp = "bcrt";

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        /* enable fallback fee on regtest */
        m_fallback_fee_enabled = true;
    }

    void SetOld()
    {
        genesis = CreateGenesisBlock(1296688602, 2, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        /*
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        */

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
    }

    /**
     * Allows modifying the Version Bits regtest parameters.
     */
    void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
    void UpdateVersionBitsParametersFromArgs(const ArgsManager& args);
};

void CRegTestParams::UpdateVersionBitsParametersFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-vbparams")) return;

    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams;
        boost::split(vDeploymentParams, strDeployment, boost::is_any_of(":"));
        if (vDeploymentParams.size() != 3) {
            throw std::runtime_error("Version bits parameters malformed, expecting deployment:start:end");
        }
        int64_t nStartTime, nTimeout;
        if (!ParseInt64(vDeploymentParams[1], &nStartTime)) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        if (!ParseInt64(vDeploymentParams[2], &nTimeout)) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        bool found = false;
        for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                UpdateVersionBitsParameters(Consensus::DeploymentPos(j), nStartTime, nTimeout);
                found = true;
                LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld\n", vDeploymentParams[0], nStartTime, nTimeout);
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
        }
    }
}

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

const CChainParams *pParams() {
    return globalChainParams.get();
};

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams(gArgs));
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}


void SetOldParams(std::unique_ptr<CChainParams> &params)
{
    if (params->NetworkID() == CBaseChainParams::MAIN) {
        return ((CMainParams*)params.get())->SetOld();
    }
    if (params->NetworkID() == CBaseChainParams::REGTEST) {
        return ((CRegTestParams*)params.get())->SetOld();
    }
};

void ResetParams(std::string sNetworkId, bool fVpubModeIn)
{
    // Hack to pass old unit tests
    globalChainParams = CreateChainParams(sNetworkId);
    if (!fVpubModeIn) {
        SetOldParams(globalChainParams);
    }
};

/**
 * Mutable handle to regtest params
 */
CChainParams &RegtestParams()
{
    return *globalChainParams.get();
};
