# BlockPanther

Block Panther
Fast, Reliable & Secure


# General Build Information


Ubuntu Dependencies:
===================

sudo apt-get install build-essential libtool autotools-dev automake pkg-config libssl-dev libevent-dev bsdmainutils

sudo apt-get install qt5-default qt5-qmake qtbase5-dev-tools qttools5-dev-tools build-essential libboost-dev libboost-system-dev libboost-filesystem-dev libboost-program-options-dev libboost-thread-dev libssl-dev libdb++-dev libminiupnpc-dev

sudo apt-get install software-properties-common

sudo add-apt-repository ppa:bitcoin/bitcoin

sudo apt-get update

sudo apt-get install libdb4.8-dev libdb4.8++-dev

sudo apt-get install libqrencode-dev

Ubuntu Building:
================

git clone https://github.com/BlockPanther/BlockPanther.git

cd BlockPanther/src/leveldb

sh build_detect_platform build_config.mk .

cd ..

sudo make -f makefile.unix

strip BlockPantherd

LD_LIBRARY_PATH=/usr/local/lib

export LD_LIBRARY_PATH


# General Information


Name: Block Panther
Ticker: BPN
Algorithm: x14
Type: PoW/PoS Hybrid untill block 100,000 then pure PoS after.
Max Block size: 100MB
Drift Time: 10 minutes
Maximum amount of Block-Panther: 88,000,000,000
Max Outbound connections: 32 Net Cons

16 Connections to the main node so far in different Countries.
France
Germany
United Kingdom


# Proof Of Work Information


Block Time: 35 seconds
Coinbase Maturity: 200 Blocks or 116 minutes max
Modifier interval: 35 minutes
Target timespan: 35 minutes
Last PoW Block: 100,000


# PoW Mining Structure


Block 1 - 100: for developers
Block 101 - 1000: 0 BPN per block
Block 1,001 - 10,000: 100 BPN per block
Block 10,001 - 20,000: 90 BPN per block
Block 20,001 - 30,000: 80 BPN per block
Block 30,001 - 40,000: 70 BPN per block
Block 40,001 - 50,000: 60 BPN per block
Block 50,001 - 60,000: 50 BPN per block
Block 60,001 - 70,000: 40 BPN per block
Block 70,001 - 80,000: 30 BPN per block
Block 80,001 - 90,000: 20 BPN per block
Block 90,001 - 100,000: 10 BPN per block



# Proof Of Stake Information



Proof of stake starts at block: 10,000
Block Time: 35 seconds
Minimum Staking age: 1 day
Maximum Staking age: 31 days
Coinbase Maturity: 200 Blocks
Staking Split Age: 1 day
Combined Staking threshold: 500,000 BPN


# PoS Mining Structure


Block 0 - 10,000: 0 BPN per block
Block 10,001 - 20,000: 90 BPN per block
Block 20,001 - 30,000: 80 BPN per block
Block 30,001 - 40,000: 70 BPN per block
Block 40,001 - 50,000: 60 BPN per block
Block 50,001 - 60,000: 50 BPN per block
Block 60,001 - 70,000: 40 BPN per block
Block 70,001 - 80,000: 30 BPN per block
Block 80,001 - 90,000: 20 BPN per block
Block 90,001 - 100,000: 10 BPN per block
Block 100,001 and after: 20% Interest Per year or 0.054% Daily Interest



# Port Information


rpcport = 13960
port = 13961



# Transaction Information


Transaction confirmations: 8 blocks or 4.6 minutes max
Transaction Fee: 0.00010000



# Wallet & Code Links


Github: https://github.com/BlockPanther/BlockPanther

Windows Wallet: https://github.com/BlockPanther/Wallets/blob/master/Windows

Windows Daemon: https://github.com/BlockPanther/Wallets/blob/master/Windows

Linux Wallet: https://github.com/BlockPanther/Wallets/blob/master/Linux

Linux Daemon: https://github.com/BlockPanther/Wallets/blob/master/Linux



# External Links


Website: being Re Constructed again.

Block Explorer: http://104.248.136.3:3001

Discord: https://discord.gg/vcF2Qss

Twitter: https://twitter.com/BlockPanther2

CoinHub: https://coinhub.news/cs/article/bitcointalk-newann-block-panther-x14-powpos-hybrid-fast-reliable-secure-annnew



# Mining Pools


https://thecryptominerpool.com/

https://s2.mpos-pools.com/bpn

https://pool.rig.tokyo/

https://www.0769.it/

https://www.pow-coin.com/site/mining

https://thepool.life/



# Solo Mining

create a file and name it "BlockPanther.conf"

Place the contents below into BlockPanther.conf and modify the user & password section
Code:
rpcuser=user
rpcpassword=password
rpcallowip=127.0.0.1
rpcport=13960
port=13961
listen=1
server=1
daemon=1
then save it in AppData/Roaming/BlockPanther if Windows, if on Linux then it would be placed in here ~/.BlockPanther
once done all you need to do is open Block Panther Client and point your miner to it


# Exchanges
CREX24, Yobit, CoinExchange, STEX & WADAX messaged "Awaiting Reply"


# Translations

Arabic - https://bitcointalk.org/index.php?topic=5111930