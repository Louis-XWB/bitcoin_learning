// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/miner.h>

#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <common/args.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <deploymentstatus.h>
#include <logging.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <pow.h>
#include <primitives/transaction.h>
#include <timedata.h>
#include <util/moneystr.h>
#include <validation.h>

#include <algorithm>
#include <utility>

namespace node
{

  // 更新区块的时间戳，确保它是有效的，并根据需要调整难度
  // CBlockHeader *pblock:区块头,当前正在处理的区块的头部信息
  // class CBlockHeader（header）
  // int32_t nVersion; //版本号
  // uint256 hashPrevBlock; //前一个区块的哈希值
  // uint256 hashMerkleRoot; //默克尔根
  // uint32_t nTime; //时间戳
  // uint32_t nBits; //难度值
  // uint32_t nNonce; //随机数
  // https://github.com/bitcoin/bitcoin/blob/655dc716aa6043613171a1338e22928de89a7d3e/src/primitives/block.h#L21

  // const Consensus::Params &consensusParams:共识参数
  // const CBlockIndex *pindexPrev:前一个区块的索引
  // 返回值：区块时间戳的变化量
  int64_t UpdateTime(CBlockHeader *pblock, const Consensus::Params &consensusParams, const CBlockIndex *pindexPrev)
  {
    // 获取当前区块的时间戳
    int64_t nOldTime = pblock->nTime;

    //  计算新的时间戳。这里的时间戳是当前区块的上一个区块的中位时间加一和当前时间的较大值。
    //  pindexPrev->GetMedianTimePast()获取上一个区块的中位时间，TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime())获取自纪元以来的滴答数。
    // pindexPrev：CBlockIndex https://github.com/bitcoin/bitcoin/blob/655dc716aa6043613171a1338e22928de89a7d3e/src/chain.h#L158
    // MTP GetMedianTimePast():返回中位时间，即最近11个区块的中位时间。(https://github.com/bitcoin/bitcoin/blob/655dc716aa6043613171a1338e22928de89a7d3e/src/chain.h#L301C15-L301C15)
    // 计算新区块的时间戳，以确保新区块的时间戳不小于MTP + 1
    // MTP 规则确保新区块的时间戳大于前11个区块的中位数时间戳。
    // 但是，这不意味着每个新区块的时间戳都会大于其直接前驱区块的时间戳。
    // from bip-0113: https://github.com/bitcoin/bips/blob/master/bip-0113.mediawiki
    // 修改区块时间戳
    // TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime()))：将会返回这一时刻与 epoch 时刻（1970-01-01 00:00:00 UTC）之间的总秒数。
    int64_t nNewTime{std::max<int64_t>(pindexPrev->GetMedianTimePast() + 1, TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime()))};

    if (nOldTime < nNewTime)
    {
      pblock->nTime = nNewTime;
    }

    // Updating time can change work required on testnet:
    if (consensusParams.fPowAllowMinDifficultyBlocks)
    {
      pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);
    }

    return nNewTime - nOldTime;
  }

  // 重新生成区块的commitment，这是与SegWit相关的
  // block witness data的哈希值,commitment，用于后续验证block witness data的完整性和准确性。
  // https://github.com/bitcoin/bitcoin/blob/655dc716aa6043613171a1338e22928de89a7d3e/src/validation.cpp#L3710
  void RegenerateCommitments(CBlock &block, ChainstateManager &chainman)
  {
    CMutableTransaction tx{*block.vtx.at(0)};
    tx.vout.erase(tx.vout.begin() + GetWitnessCommitmentIndex(block));
    block.vtx.at(0) = MakeTransactionRef(tx);

    const CBlockIndex *prev_block = WITH_LOCK(::cs_main, return chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock));
    chainman.GenerateCoinbaseCommitment(block, prev_block);

    block.hashMerkleRoot = BlockMerkleRoot(block);
  }

  // Limit block weight
  static BlockAssembler::Options ClampOptions(BlockAssembler::Options options)
  {
    // Limit weight to between 4K and DEFAULT_BLOCK_MAX_WEIGHT for sanity:
    options.nBlockMaxWeight = std::clamp<size_t>(options.nBlockMaxWeight, 4000, DEFAULT_BLOCK_MAX_WEIGHT);
    return options;
  }

  // BlockAssembler constructor
  // chainstate ： Chainstate current block info/state
  // mempool：CTxMemPool
  // CTxMemPool stores valid-according-to-the-current-best-chain transactions that may be included in the next block.
  // https://github.com/bitcoin/bitcoin/blob/655dc716aa6043613171a1338e22928de89a7d3e/src/txmempool.h#L301
  // options：BlockAssembler::Options
  BlockAssembler::BlockAssembler(Chainstate &chainstate, const CTxMemPool *mempool, const Options &options)
      : chainparams{chainstate.m_chainman.GetParams()},
        m_mempool{mempool},
        m_chainstate{chainstate},
        m_options{ClampOptions(options)}
  {
  }

  // terminal command args options
  void ApplyArgsManOptions(const ArgsManager &args, BlockAssembler::Options &options)
  {
    // Block resource limits
    options.nBlockMaxWeight = args.GetIntArg("-blockmaxweight", options.nBlockMaxWeight);
    if (const auto blockmintxfee{args.GetArg("-blockmintxfee")})
    {
      if (const auto parsed{ParseMoney(*blockmintxfee)})
        options.blockMinFeeRate = CFeeRate{*parsed};
    }
  }

  // same as above
  static BlockAssembler::Options ConfiguredOptions()
  {
    BlockAssembler::Options options;
    ApplyArgsManOptions(gArgs, options);
    return options;
  }

  // another BlockAssembler constructor
  // use configured options to initialize BlockAssembler
  BlockAssembler::BlockAssembler(Chainstate &chainstate, const CTxMemPool *mempool)
      : BlockAssembler(chainstate, mempool, ConfiguredOptions()) {}

  // reset block data
  void BlockAssembler::resetBlock()
  {
    inBlock.clear();
    // inBlock: tx selected for block inclusion

    // Reserve space for coinbase tx
    nBlockWeight = 4000;
    nBlockSigOpsCost = 400;

    // These counters do not include coinbase tx
    nBlockTx = 0;
    nFees = 0;
  }

  std::unique_ptr<CBlockTemplate> BlockAssembler::CreateNewBlock(const CScript &scriptPubKeyIn)
  {
    const auto time_start{SteadyClock::now()}; // record time start

    resetBlock(); // reset block data

    pblocktemplate.reset(new CBlockTemplate()); // create new block template

    if (!pblocktemplate.get()) // check if block template is created
    {
      return nullptr;
    }
    CBlock *const pblock = &pblocktemplate->block;
    // pointer new block template
    // pointer for convenience

    // Add dummy coinbase tx as first transaction
    pblock->vtx.emplace_back();                  // add coinbase tx（empty block, auto create）
    pblocktemplate->vTxFees.push_back(-1);       // updated at end
    pblocktemplate->vTxSigOpsCost.push_back(-1); // updated at end

    LOCK(::cs_main);
    CBlockIndex *pindexPrev = m_chainstate.m_chain.Tip();
    // get the latest block index
    // m_chainstate： ChainstateManager
    // ChainstateManager：保存了有关区块链当前状态的信息,管理UTXO数据。
    // m_chain: CChain(std::vector<CBlockIndex*> vChain) ：区块索引的列表，按照区块的高度排序。(https://github.com/bitcoin/bitcoin/blob/655dc716aa6043613171a1338e22928de89a7d3e/src/chain.h#L455)
    // Tip(): Returns the index entry for the tip of this chain, or nullptr if none.
    assert(pindexPrev != nullptr);
    nHeight = pindexPrev->nHeight + 1; // new block height

    pblock->nVersion = m_chainstate.m_chainman.m_versionbitscache.ComputeBlockVersion(pindexPrev, chainparams.GetConsensus());
    // Compute the block version to use for the next block,
    // based on the median version of the last X blocks.
    // block version
    // https://medium.com/fcats-blockchain-incubator/understanding-the-bitcoin-blockchain-header-a2b0db06b515#:~:text=Version-,%E7%89%88%E6%9C%AC,-Version%20Field%20of

    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    // test environment only
    if (chainparams.MineBlocksOnDemand())
    {
      pblock->nVersion = gArgs.GetIntArg("-blockversion", pblock->nVersion);
    }

    // set block time
    pblock->nTime = TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime());

    // get last block middle time
    m_lock_time_cutoff = pindexPrev->GetMedianTimePast();

    int nPackagesSelected = 0;
    int nDescendantsUpdated = 0;
    if (m_mempool) // check if mempool is created
    {
      LOCK(m_mempool->cs);
      addPackageTxs(*m_mempool, nPackagesSelected, nDescendantsUpdated);
      // addPackageTxs: add txs to block
    }

    // record current time
    const auto time_1{SteadyClock::now()};

    m_last_block_num_txs = nBlockTx;    // last block txs amount
    m_last_block_weight = nBlockWeight; // last block weight

    // Create coinbase transaction.
    CMutableTransaction coinbaseTx;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout.SetNull(); // coinbase input no prevout
    coinbaseTx.vout.resize(1);
    coinbaseTx.vout[0].scriptPubKey = scriptPubKeyIn; // miner address
    coinbaseTx.vout[0].nValue = nFees + GetBlockSubsidy(nHeight, chainparams.GetConsensus());
    // nFees: block fees
    // block subsidy: https://en.bitcoin.it/wiki/Controlled_supply

    coinbaseTx.vin[0].scriptSig = CScript() << nHeight << OP_0;
    pblock->vtx[0] = MakeTransactionRef(std::move(coinbaseTx));
    pblocktemplate->vchCoinbaseCommitment = m_chainstate.m_chainman.GenerateCoinbaseCommitment(*pblock, pindexPrev);
    pblocktemplate->vTxFees[0] = -nFees;

    LogPrintf("CreateNewBlock(): block weight: %u txs: %u fees: %ld sigops %d\n", GetBlockWeight(*pblock), nBlockTx, nFees, nBlockSigOpsCost);

    // Fill in header
    // last block hash
    pblock->hashPrevBlock = pindexPrev->GetBlockHash();

    // set block time
    UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev);

    // set block nBits: difficulty
    pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, chainparams.GetConsensus());

    // initial block nonce as 0
    // miner will plus 1 to find the right nonce
    pblock->nNonce = 0;

    // calculate coinbase tx sigOps cost
    pblocktemplate->vTxSigOpsCost[0] = WITNESS_SCALE_FACTOR * GetLegacySigOpCount(*pblock->vtx[0]);

    // store block validation state
    // check if block is valid
    BlockValidationState state;
    if (m_options.test_block_validity && !TestBlockValidity(state, chainparams, m_chainstate, *pblock, pindexPrev,
                                                            GetAdjustedTime, /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/false))
    {
      throw std::runtime_error(strprintf("%s: TestBlockValidity failed: %s", __func__, state.ToString()));
    }

    // record current time,use to calculate time cost
    const auto time_2{SteadyClock::now()};

    // record block details
    // and cost time
    LogPrint(BCLog::BENCH, "CreateNewBlock() packages: %.2fms (%d packages, %d updated descendants), validity: %.2fms (total %.2fms)\n",
             Ticks<MillisecondsDouble>(time_1 - time_start), nPackagesSelected, nDescendantsUpdated,
             Ticks<MillisecondsDouble>(time_2 - time_1),
             Ticks<MillisecondsDouble>(time_2 - time_start));

    // return new block template, ready to mine
    return std::move(pblocktemplate);
  }

  // filter txs that already in block
  // testSet contains txs waiting to be tested, we only test txs that are not in block
  void BlockAssembler::onlyUnconfirmed(CTxMemPool::setEntries &testSet)
  {
    for (CTxMemPool::setEntries::iterator iit = testSet.begin(); iit != testSet.end();)
    {
      // Only test txs not already in the block
      if (inBlock.count(*iit))
      {
        testSet.erase(iit++);
      }
      else
      {
        iit++;
      }
    }
  }

  // Package： a set of transactions that can be included in a block
  //  wait to be tested txs
  //  selected from mempool
  // TestPackage: check if package is valid
  // consider block weight and sigOps cost
  bool BlockAssembler::TestPackage(uint64_t packageSize, int64_t packageSigOpsCost) const
  {
    // TODO: switch to weight-based accounting for packages instead of vsize-based accounting.
    // check block weight greater than max block weight after adding this package
    if (nBlockWeight + WITNESS_SCALE_FACTOR * packageSize >= m_options.nBlockMaxWeight)
    {
      return false;
    }

    // check block sigOps cost greater than max block sigOps cost after adding this package
    if (nBlockSigOpsCost + packageSigOpsCost >= MAX_BLOCK_SIGOPS_COST)
    {
      return false;
    }
    return true;
  }

  // Perform transaction-level checks before adding to block:
  // - transaction finality (locktime)
  // check every tx in package can be included in block
  bool BlockAssembler::TestPackageTransactions(const CTxMemPool::setEntries &package) const
  {
    for (CTxMemPool::txiter it : package)
    {
      // https://github.com/bitcoin/bitcoin/blob/655dc716aa6043613171a1338e22928de89a7d3e/src/consensus/tx_verify.cpp#L17
      // LOCKTIME_THRESHOLD = 500000000： https://github.com/bitcoin/bitcoin/blob/655dc716aa6043613171a1338e22928de89a7d3e/test/functional/test_framework/script.py#L31
      if (!IsFinalTx(it->GetTx(), nHeight, m_lock_time_cutoff))
      {
        return false;
      }
    }
    return true;
  }

  // add tx to block
  void BlockAssembler::AddToBlock(CTxMemPool::txiter iter)
  {
    // add tx from mempool to new block txs list
    pblocktemplate->block.vtx.emplace_back(iter->GetSharedTx());

    // add tx fee to new block txs fee list
    pblocktemplate->vTxFees.push_back(iter->GetFee());

    // add tx sigOps cost to new block txs sigOps cost list
    pblocktemplate->vTxSigOpsCost.push_back(iter->GetSigOpCost());

    // refresh block weight
    nBlockWeight += iter->GetTxWeight();

    // auto add 1 to tx count
    ++nBlockTx;

    // refresh block sigOps cost
    nBlockSigOpsCost += iter->GetSigOpCost();

    // refresh block fees
    nFees += iter->GetFee();

    // add tx to inBlock set, means this tx is already in block
    inBlock.insert(iter);

    // check has set "-printpriority" option
    bool fPrintPriority = gArgs.GetBoolArg("-printpriority", DEFAULT_PRINTPRIORITY);
    if (fPrintPriority)
    {
      LogPrintf("fee rate %s txid %s\n",
                CFeeRate(iter->GetModifiedFee(), iter->GetTxSize()).ToString(),
                iter->GetTx().GetHash().ToString());
    }
  }

  /** Add descendants of given transactions to mapModifiedTx with ancestor
   * state updated assuming given transactions are inBlock. Returns number
   * of updated descendants. */
  static int UpdatePackagesForAdded(const CTxMemPool &mempool,
                                    const CTxMemPool::setEntries &alreadyAdded,
                                    indexed_modified_transaction_set &mapModifiedTx) EXCLUSIVE_LOCKS_REQUIRED(mempool.cs)
  {
    AssertLockHeld(mempool.cs);

    int nDescendantsUpdated = 0;

    for (CTxMemPool::txiter it : alreadyAdded)
    {
      CTxMemPool::setEntries descendants;

      // Calculate in-mempool descendants of this tx
      mempool.CalculateDescendants(it, descendants);

      // Insert all descendants (not yet in block) into the modified set
      for (CTxMemPool::txiter desc : descendants)
      {
        // Skip if already in block
        if (alreadyAdded.count(desc))
        {
          continue;
        }
        ++nDescendantsUpdated;

        // find descendant tx in mapModifiedTx
        modtxiter mit = mapModifiedTx.find(desc);

        if (mit == mapModifiedTx.end())
        {
          //if descendant tx not in mapModifiedTx, create a new entry and insert it
          CTxMemPoolModifiedEntry modEntry(desc);
          mit = mapModifiedTx.insert(modEntry).first;
        }

        // update descendant tx's ancestor state
        mapModifiedTx.modify(mit, update_for_parent_inclusion(it));
      }
    }

    // Return number of updated descendants
    return nDescendantsUpdated;
  }

  void BlockAssembler::SortForBlock(const CTxMemPool::setEntries &package, std::vector<CTxMemPool::txiter> &sortedEntries)
  {
    // Sort package by ancestor count
    // If a transaction A depends on transaction B, then A's ancestor count
    // must be greater than B's.  So this is sufficient to validly order the
    // transactions for block inclusion.
    sortedEntries.clear();
    sortedEntries.insert(sortedEntries.begin(), package.begin(), package.end());
    std::sort(sortedEntries.begin(), sortedEntries.end(), CompareTxIterByAncestorCount());
  }

  // This transaction selection algorithm orders the mempool based
  // on feerate of a transaction including all unconfirmed ancestors.
  // Since we don't remove transactions from the mempool as we select them
  // for block inclusion, we need an alternate method of updating the feerate
  // of a transaction with its not-yet-selected ancestors as we go.
  // This is accomplished by walking the in-mempool descendants of selected
  // transactions and storing a temporary modified state in mapModifiedTxs.
  // Each time through the loop, we compare the best transaction in
  // mapModifiedTxs with the next transaction in the mempool to decide what
  // transaction package to work on next.
  void BlockAssembler::addPackageTxs(const CTxMemPool &mempool, int &nPackagesSelected, int &nDescendantsUpdated)
  {
    AssertLockHeld(mempool.cs);

    // mapModifiedTx will store sorted packages after they are modified
    // because some of their txs are already in the block
    // store modified txs(some of their txs are already in the block)
    indexed_modified_transaction_set mapModifiedTx;

    // Keep track of entries that failed inclusion, to avoid duplicate work
    // store fail txs
    CTxMemPool::setEntries failedTx;

    //get iterator(mi) of mempool, use to iterate total txs in mempool
    CTxMemPool::indexed_transaction_set::index<ancestor_score>::type::iterator mi = mempool.mapTx.get<ancestor_score>().begin();
    
    CTxMemPool::txiter iter;

    // Limit the number of attempts to add transactions to the block when it is
    // close to full; this is just a simple heuristic to finish quickly if the
    // mempool has a lot of entries.
    const int64_t MAX_CONSECUTIVE_FAILURES = 1000;
    int64_t nConsecutiveFailed = 0;

    //when mempool is not empty
    while (mi != mempool.mapTx.get<ancestor_score>().end() || !mapModifiedTx.empty())
    {
      // First try to find a new transaction in mapTx to evaluate.
      //
      // Skip entries in mapTx that are already in a block or are present
      // in mapModifiedTx (which implies that the mapTx ancestor state is
      // stale due to ancestor inclusion in the block)
      // Also skip transactions that we've already failed to add. This can happen if
      // we consider a transaction in mapModifiedTx and it fails: we can then
      // potentially consider it again while walking mapTx.  It's currently
      // guaranteed to fail again, but as a belt-and-suspenders check we put it in
      // failedTx and avoid re-evaluation, since the re-evaluation would be using
      // cached size/sigops/fee values that are not actually correct.
      /** Return true if given transaction from mapTx has already been evaluated,
       * or if the transaction's cached data in mapTx is incorrect. */
      if (mi != mempool.mapTx.get<ancestor_score>().end())
      {
        auto it = mempool.mapTx.project<0>(mi);
        assert(it != mempool.mapTx.end());
        //add ancestor tx first
        if (mapModifiedTx.count(it) || inBlock.count(it) || failedTx.count(it))
        {
          ++mi;
          continue;
        }
      }

      // Now that mi is not stale, determine which transaction to evaluate:
      // the next entry from mapTx, or the best from mapModifiedTx?
      bool fUsingModified = false;

      modtxscoreiter modit = mapModifiedTx.get<ancestor_score>().begin();

      // if mempool.mapTx is empty, use mapModifiedTx
      if (mi == mempool.mapTx.get<ancestor_score>().end())
      {
        // We're out of entries in mapTx; use the entry from mapModifiedTx
        iter = modit->iter;
        fUsingModified = true;
      }
      else
      {
        // Try to compare the mapTx entry to the mapModifiedTx entry
        // inter in mempool.mapTx
        iter = mempool.mapTx.project<0>(mi);
        if (modit != mapModifiedTx.get<ancestor_score>().end() &&
            CompareTxMemPoolEntryByAncestorFee()(*modit, CTxMemPoolModifiedEntry(iter)))
        {
          // The best entry in mapModifiedTx has higher score
          // than the one from mapTx.
          // Switch which transaction (package) to consider
          iter = modit->iter;
          fUsingModified = true;
        }
        else
        {
          // Either no entry in mapModifiedTx, or it's worse than mapTx.
          // Increment mi for the next loop iteration.
          ++mi;
        }
      }

      // We skip mapTx entries that are inBlock, and mapModifiedTx shouldn't
      // contain anything that is inBlock.
      assert(!inBlock.count(iter));

      uint64_t packageSize = iter->GetSizeWithAncestors();//get package size
      CAmount packageFees = iter->GetModFeesWithAncestors();//get package fees
      int64_t packageSigOpsCost = iter->GetSigOpCostWithAncestors();//get package sigOps cost

      // If using the modified set, we need to update the values for this
      if (fUsingModified)
      {
        packageSize = modit->nSizeWithAncestors;//get package size
        packageFees = modit->nModFeesWithAncestors;//get package fees
        packageSigOpsCost = modit->nSigOpCostWithAncestors;//get package sigOps cost
      }

      //check package fee < min rate
      if (packageFees < m_options.blockMinFeeRate.GetFee(packageSize))
      {
        // Everything else we might consider has a lower fee rate
        return;
      }

      //check package size and sigOps cost
      if (!TestPackage(packageSize, packageSigOpsCost))
      {
        if (fUsingModified)
        {
          // Since we always look at the best entry in mapModifiedTx,
          // we must erase failed entries so that we can consider the
          // next best entry on the next loop iteration
          mapModifiedTx.get<ancestor_score>().erase(modit);
          failedTx.insert(iter);
        }

        ++nConsecutiveFailed;

        if (nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES && nBlockWeight >
                                                                 m_options.nBlockMaxWeight - 4000)
        {
          // Give up if we're close to full and haven't succeeded in a while
          break;
        }
        continue;
      }

      //get tx ancestors
      auto ancestors{mempool.AssumeCalculateMemPoolAncestors(__func__, *iter, CTxMemPool::Limits::NoLimits(), /*fSearchForParents=*/false)};

      //check ancestors tx not in block, delete tx in block
      onlyUnconfirmed(ancestors);

      //insert iter to ancestors
      ancestors.insert(iter);

      // Test if all tx's are Final
      if (!TestPackageTransactions(ancestors))
      {
        if (fUsingModified)
        {
          mapModifiedTx.get<ancestor_score>().erase(modit);
          failedTx.insert(iter);
        }
        continue;
      }

      // This transaction will make it in; reset the failed counter.
      nConsecutiveFailed = 0;

      // Package can be added. Sort the entries in a valid order.
      std::vector<CTxMemPool::txiter> sortedEntries;
      SortForBlock(ancestors, sortedEntries);

      for (size_t i = 0; i < sortedEntries.size(); ++i)
      {
        AddToBlock(sortedEntries[i]);//add tx to block
        // Erase from the modified set, if present
        mapModifiedTx.erase(sortedEntries[i]);
      }

      ++nPackagesSelected;

      // Update transactions that depend on each of these
      nDescendantsUpdated += UpdatePackagesForAdded(mempool, ancestors, mapModifiedTx);
    }
  }
} // namespace node