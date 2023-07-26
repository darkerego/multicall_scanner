#!/usr/bin/env python3
import argparse
import asyncio
import binascii
import itertools
import json
import math
import multiprocessing
import os
import pickle
import pprint
import time
from asyncio.exceptions import TimeoutError
from itertools import cycle

import aiofiles
import dotenv
import eth_utils
import rlp
import trio
import trio_parallel
import web3
from eth_utils import keccak, to_checksum_address, to_bytes
from tqdm.asyncio import tqdm as tqdma, tqdm
# import nest_asyncio
from web3 import Web3, HTTPProvider, WebsocketProvider
from websockets.exceptions import ConnectionClosedError

from lib import abi_lib
from lib import style
# from tqdm import tqdm
from lib.multicalls import MultiCalls
import mnemonic
web3.Account.enable_unaudited_hdwallet_features()
from_mnemonic = web3.Account.from_mnemonic
import lib.mnem_utils
def loop(n):
    # Arbitrary CPU-bound work
    for _ in range(n):
        pass
    print("Loops completed:", n)


# nest_asyncio.apply()
dotenv.load_dotenv()
# INFURA/Quicknode jackdawson22s@proton.me qL4VPiY3FQCgsMD!!
ethereum_http_rpcs = ['https://side-fragrant-sponge.quiknode.pro/d93bdc69142e7a6c8cccc899d6b6fc1d8f181574/']
ethereumws_rpcs = ['wss://side-fragrant-sponge.quiknode.pro/d93bdc69142e7a6c8cccc899d6b6fc1d8f181574/']

arbitrum_http_rpcs = [
    'https://clean-weathered-darkness.arbitrum-mainnet.quiknode.pro/2de34757a5af3c27786774230a3230182e431e66/']
arbitrum_ws_rpcs = [
    'wss://clean-weathered-darkness.arbitrum-mainnet.quiknode.pro/2de34757a5af3c27786774230a3230182e431e66/']

polygon_http_rpcs = ['https://wild-orbital-glitter.matic.quiknode.pro/c7c93f2caa2444b2f381b693a16fe4099f4243de/']
polygon_ws_rpcs = ['wss://wild-orbital-glitter.matic.quiknode.pro/c7c93f2caa2444b2f381b693a16fe4099f4243de/']

binance_http_rpcs = ['https://broken-wispy-river.bsc.quiknode.pro/83d7e47d6f7933811d7d07978f9e868cd1b9e765/']
binance_ws_rpcs = ['wss://broken-wispy-river.bsc.quiknode.pro/83d7e47d6f7933811d7d07978f9e868cd1b9e765/']

optimism_http_rpcs = ['https://greatest-proud-yard.optimism.quiknode.pro/8d86b0275bfd82ea2177ff0361d41989b6664660/']
optimism_ws_rpcs = ['wss://greatest-proud-yard.optimism.quiknode.pro/8d86b0275bfd82ea2177ff0361d41989b6664660/']

BINANCE_CONTRACT = '0x55dC97d34FE93cBff8BA3C8c66A81dDB43036FA4'
ETHEREUM_CONTRACT = '0x391FDee1605F69507A94e3aAdc00713D088b836D'
ARBITRUM_CONTRACT = '0x7BA229d212B1A54A66EFA4e7dBefC82Dc906bF2b'
POLYGON_CONTRACT = '0xB97Fbf5046688aD1A987B4F85A857ded99f82c70'
OPTIMISM_CONTRACT = '0x19D31942ac5E38E0350fdf305cDE36B6929595b3'
mnem = mnemonic.Mnemonic("english")


class ScanReport:
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.report_dict = {}
        self.time_stamp = time.time()

    def add_wallet(self, eth, key, address):
        if self.report_dict.get(address):
            return
        self.report_dict.update({address: {'private_key': key, 'eth': eth, 'tokens': []}})
        # asyncio.create_task(self.dump_report())

    def update_native_balance(self, balance):
        self.report_dict['address']['eth'] = balance

    def add_token(self, token_address, token_balance, token_symbol, address):
        self.report_dict[address]['tokens'].append({'symbol': token_symbol,
                                                    'balance': token_balance,
                                                    'contract': token_address})
        # asyncio.create_task(self.dump_report())

    async def dump_report(self, obj=None):
        async with aiofiles.open(f'reports/{self.log_file}_{self.time_stamp}.json', 'w') as f:
            if not obj:
                await f.write(json.dumps(self.report_dict))
            else:
                await f.write(json.dumps(obj))

    async def calculate(self):
        print('[+] Calculating ... ')
        report_dict = {}
        for wallet, v in self.report_dict.items():
            if v:
                if len(v.get('tokens')):
                    for token in v.get('tokens'):
                        if float(token.get('balance')) > 0:
                            report_dict.update({wallet: v})
                if v.get('balance') and v.get('balance') > 0:
                    report_dict.update({wallet: v})
                    #print(f'[+] {v}')
        await self.dump_report(report_dict)


class Acct:
    def __init__(self, key=None, mnemonic=None):
        acct = None
        if key:
            acct = web3.Account.from_key(key.strip('\r\n'))
        else:
            if mnemonic:
                key=lib.mnem_utils.get_account(mnemonic)
                acct = from_key(key)

        if not acct:
            return
        self.key = acct.key.hex()
        self.address = acct.address
        self._dict = {'key': self.key, 'address': self.address}

    def __hash__(self):
        return id(self.address)

    def __eq__(self, other):
        return id(self.address) == id(other.address)

    @property
    def __dict__(self):
        return self._dict


class NonsenseError(Exception):
    pass


class BlitzScan:
    def __init__(self, network, tokens=None, outfile=None):
        self.token_total = 0
        self.eth_total = 0
        self.total_scanned = 0
        self.keys = []
        self.outfile = outfile
        self._connection = None
        self.network = network
        self.acct_dict = {}
        self.report_dict = {}
        self.session_report = ScanReport(outfile)
        self.endpoint = os.environ.get(f'{network}_http_endpoint')
        self.ws_endpoint = os.environ.get(f'{network}_ws_endpoint')
        self.printer = style.PrettyText()
        self.concurrent_tasks = 0
        w3_arr = self.setup_rpc()
        self.w3_arr = cycle(w3_arr)
        self.tokens = tokens
        self.now = time.time()
        self.token_map = {}
        if tokens:
            self.setup_erc20()
        self.accounts = []
        if network == 'ethereum':
            self.mc = MultiCalls(self.w3_arr, bal_con=ETHEREUM_CONTRACT)
        elif network == 'arbitrum':
            self.mc = MultiCalls(self.w3_arr, bal_con=ARBITRUM_CONTRACT)
        elif network == 'polygon':
            self.mc = MultiCalls(self.w3_arr, bal_con=POLYGON_CONTRACT)
        elif network == 'optimism':
            self.mc = MultiCalls(self.w3_arr, bal_con=OPTIMISM_CONTRACT)
        else:
            self.mc = MultiCalls(self.w3_arr, bal_con=BINANCE_CONTRACT)
        self.hits = {}
        if self.tokens:
            self.setup_erc20()
        if not self.outfile:
            self.outfile = f'output/keyscan_{time.time()}.json'
        else:
            self.outfile = f'output/{outfile}_{time.time()}.json'

    def setup_rpc(self):
        w3_arr = []
        if self.network == 'ethereum':
            http_rpcs = ethereum_http_rpcs
            ws_rpcs = ethereumws_rpcs
        elif self.network == 'arbitrum':
            http_rpcs = arbitrum_http_rpcs
            ws_rpcs = arbitrum_ws_rpcs
        elif self.network == 'optimism':
            http_rpcs = optimism_http_rpcs
            ws_rpcs = optimism_ws_rpcs
        elif self.network == 'polygon':
            http_rpcs = polygon_http_rpcs
            ws_rpcs = polygon_ws_rpcs
        else:
            http_rpcs = binance_http_rpcs
            ws_rpcs = binance_ws_rpcs
        for url in http_rpcs:
            w3_arr.append(Web3(HTTPProvider(url)))
        for url in ws_rpcs:
            w3_arr.append(Web3(WebsocketProvider(url)))
        return w3_arr

    @property
    def connection(self) -> web3.Web3:
        w3 = next(self.w3_arr)
        return w3

    def reconnect_ws(self):
        w3_arr = self.setup_rpc()
        self.w3_arr = cycle(w3_arr)

    def divide_chunks(self, l: list, n: int):
        for i in range(0, len(l), n):
            yield l[i:i + n]

    def setup_erc20(self):
        self.printer.good('Getting token metadata ... ')
        if self.tokens:
            for token in self.tokens:
                # for token in self.tokens:
                contract = self.connection.eth.contract(token, abi=abi_lib.EIP20_ABI)
                decimals = {'decimals': contract.functions.decimals().call()}
                symbol = {'symbol': contract.functions.symbol().call()}
                self.token_map[contract.address] = {}
                self.token_map[token].update(decimals)
                self.token_map[token].update(symbol)
        # print(self.token_map)

    def native_balance_single(self, account):
        return self.connection.eth.get_balance(account.address)

    def get_nonce(self, account):
        return self.connection.eth.get_transaction_count(account.get('address'))

    def tx_count(self, account):
        return self.connection.eth.get_transaction_count(account.address)

    async def run_account(self, account):
        try:
            txc = self.get_nonce(account)
        except ConnectionClosedError:
            self.reconnect_ws()
            return await self.run_account(account)
        else:
            return txc

    def __find_key(self, addr):
        ret = None
        current_ids = set(acct for acct in self.accounts)
        for cid in current_ids:
            if cid.address == addr:
                ret = cid.key.hex()
        if not ret:
            raise NonsenseError
        return ret

    @staticmethod
    def find_key(addr, kb):
        for acct in kb:
            if acct:
                if acct['address'] == addr:
                    return acct['key']

    def add_call_eth(self, address):
        self.mc.add_call_get_balance(address)

    def add_call_erc20(self, address, token):
        self.mc.add_call_get_erc20_balance(address, token)

    async def start_nonce_loop(self):
        progress = tqdm(self.accounts)
        progress.desc = str({'Hits': len(self.hits)})
        contract_addresses = []
        calls = []
        for account in progress:
            #txc = await self.run_account(account)
            if account:
                nonce = self.get_nonce(account)
                for x in range(args.max_nonce):
                    contract_addresses.append(self._mk_contract_address(account.get('address'), nonce+x))
            """if txc > 0:
                self.hits[account.address] = {'nonce': txc}
                progress.desc = str({'Hits': len(self.hits)})
                print(f'{account.address}: TXC: {txc}')"""
        for acct in contract_addresses:
            calls.append(self.mc.add_call_get_balance(acct))
        acct_batches = self.divide_chunks(contract_addresses, args.call_batch)
        acct_batches = [z for z in acct_batches]
        batches = self.divide_chunks(calls, args.call_batch)
        batches = [xx for xx in batches]
        batches = tqdm(batches)
        for call_batch, acct_batch in zip(batches, acct_batches):
            #ret = await self.mc.run(calls=call_batch)
            #await self.parse_calls_single_mode(ret, acct_batch)
            await self.multicall_task(call_batch, acct_batch)

        await asyncio.sleep(1)
        print(f'[+] Found {len(self.hits)}')

    def _mk_contract_address(self, sender: str, nonce: int) -> str:
        """Create a contract address using eth-utils.

        # https://ethereum.stackexchange.com/a/761/620
        """
        sender_bytes = to_bytes(hexstr=sender)
        raw = rlp.encode([sender_bytes, nonce])
        h = keccak(raw)
        address_bytes = h[12:]
        return to_checksum_address(address_bytes)

    def compute_contract_address(self, address, nonce):
        return to_checksum_address(self._mk_contract_address(to_checksum_address(address), nonce))

    async def logger(self, text):
        async with aiofiles.open(self.outfile, 'a') as ff:
            await ff.write(str(text + '\n'))

    async def w3_call(self, fn, *args, **kwargs):
        ret = False
        sleeper = 1
        for i in range(5):
            try:
                ret = fn(*args, **kwargs)
            except TimeoutError:
                sleeper += sleeper
                await asyncio.sleep(sleeper)
            finally:
                return ret

    async def parse_calls_single_mode(self, results, kb):
        # find_key = self.find_key
        bal_str = 0.0
        eth_bal = 0.0
        for k, v in results.items():
            if not v:
                raise NonsenseError
            # print(k,v)
            identifier = k.split('_')
            wallet_addr, token_addr = identifier[0],  identifier[1]
            if token_addr == '0x0000000000000000000000000000000000000000':
                if v[0] > 0:
                    eth_bal = v[0] / (10 ** int(18))
                else:
                    eth_bal = 0.0
                bal_str = '{:f}'.format(eth_bal)
                self.session_report.update_native_balance(eth_bal)
                self.eth_total += float(eth_bal)
            else:
                decimals = self.token_map.get(token_addr).get('decimals')
                symbol = self.token_map.get(token_addr).get('symbol')
                if v[0] > 0:
                    tok_bal = v[0] / 10 ** int(decimals)
                else:
                    tok_bal = 0.0
                tok_bal_str = '{:f}'.format(tok_bal)
                self.session_report.add_token(token_addr, tok_bal_str, symbol, wallet_addr)
                self.token_total += float(tok_bal)
                if eth_bal > 0 or tok_bal > 0:
                    pprint.pprint({'address': wallet_addr, 'balance': bal_str,
                                   'token': {'address': token_addr, 'balance': tok_bal_str}})

    async def parse_calls(self, token_addr, results, kb):
        self.printer.normal('Parsing returned data ... ')
        # for token in self.token_map:
        if not args.dual_mode:
            return await self.parse_calls_single_mode(results, kb)
        decimals = self.token_map.get(token_addr).get('decimals')
        symbol = self.token_map.get(token_addr).get('symbol')
        find_key = self.find_key
        for k, v in results.items():
            if not v:
                raise NonsenseError
            if v[0] > 0 or v[1] > 0:
                if v[0] > 0:
                    eth_bal = v[0] / (10 ** int(18))
                else:
                    eth_bal = 0.0
                if v[1] > 0:
                    tok_bal = v[1] / 10 ** int(decimals)
                else:
                    tok_bal = 0.0
                bal_str = '{:f}'.format(eth_bal)
                tok_bal_str = '{:f}'.format(tok_bal)
                key = find_key(k, kb)
                log_msg = {'address': k, 'key': key, 'eth': bal_str, symbol: tok_bal_str}
                pprint.pprint(log_msg)
                self.session_report.add_wallet(bal_str, key, k)
                self.session_report.add_token(token_addr, tok_bal_str, symbol, k)
                # await self.log_entry(k, key, float(eth_bal), symbol, token_addr, float(tok_bal))
                self.token_total += float(tok_bal)
                self.eth_total += float(eth_bal)

    async def multicall_task(self, calls, kb):
        self.concurrent_tasks += 1
        ret = await self.mc.run(calls=calls)
        self.concurrent_tasks -= 1
        if args.dual_mode:
            tokens = self.tokens[0]
        else:
            tokens = self.tokens
        asyncio.create_task(self.parse_calls(tokens, ret, kb))

    async def start_loop_calculate_multiple_contracts(self):
        calls = []
        self.printer.normal(f'Calculating calls ... ')
        for account in self.accounts:
            if not account:
                print('None account')
            else:
                self.session_report.add_wallet(0, account['key'], account['address'])
                if account:
                    self.mc.add_call_get_balance(account['address'])
            for contract_address in self.tokens:
                # token_decimals = self.token_map.get(contract_address).get('decimals')
                # token_symbol = self.token_map[contract_address]['symbol']
                # print(f'[+] Processing token {token_symbol}')

                if account:
                    addr = account['address']
                    # print(account.get('address'))
                    call = self.mc.add_call_get_erc20_balance(to_checksum_address(addr),
                                                              to_checksum_address(contract_address))
                    calls.append(call)

        self.printer.normal('Finished calculating calls.')
        #
        if len(calls) > args.call_batch:
            call_batches = self.divide_chunks(calls, args.call_batch)
        else:
            call_batches = [calls]
        _batches = [x for x in call_batches]
        progress = tqdma(_batches, total=int(+1))
        print(f'[~] Batches: {len(_batches)}')
        for x, cb in enumerate(progress):
            # print(f'Batch size: {len(cb)}')
            await self.multicall_task(cb, self.accounts)

    async def start_loop_calculate_contracts(self):
        contract_address = self.tokens[0]
        # print('Calculating calls ... ')
        if not contract_address:
            token_symbol = 'ETH'
            self.printer.good("Starting multicalls ... ")
        else:
            # contract = self.connection.eth.contract(token, abi=abi_lib.EIP20_ABI)
            # contract_addr = token
            # token_decimals = self.token_map.get(contract_address).get('decimals')
            token_symbol = self.token_map.get(contract_address).get('symbol')
            self.printer.normal(f'Calculating calls ... ')
        if len(self.accounts) > args.call_batch:
            key_batches = self.divide_chunks(self.accounts, args.call_batch, )
        else:
            key_batches = [self.accounts]
        print(f'[~] Have {len(self.accounts)} accounts in memory ...')
        print(f'First acct: {self.accounts[0]}')
        # add_call_get_balance = self.mc.add_call_get_balance
        # add_call_get_erc20_balance = self.mc.add_call_get_erc20_balance
        add_call_dual_balance = self.mc.add_call_dual_balance
        # _find_key = self._find_key
        _find_key = self.__find_key
        # logger = self.logger
        _tot = int(len(self.accounts) / args.call_batch)
        progress = tqdma(key_batches, total=_tot)
        print(f'[~] Batches: {progress}')
        calls = []
        # tasks = set()
        for x, kb in enumerate(progress):
            for account in kb:
                if account:
                    addr = account.get('address')
                    # print(account.get('address'))
                    call = add_call_dual_balance(to_checksum_address(addr), to_checksum_address(self.tokens[0]))
                    calls.append(call)
            # asyncio.create_task(self.multicall_task(calls))
            self.printer.normal('Sending batch request .. ')
            await asyncio.sleep(0.0001)
            # print(f'Adding batch. Batch %s/%s' %(x, _tot))
            await self.multicall_task(calls, kb)
            calls = []
            self.mc.calls.clear()
            progress.set_postfix_str("Total %s: %s Total ETH: %s Concurrency: %s" % (
                token_symbol, self.token_total, self.eth_total, self.concurrent_tasks))
        self.printer.good('Finished calls')

    async def start_loop(self):
        if args.dual_mode:
            await self.start_loop_calculate_contracts()
        else:
            await self.start_loop_calculate_multiple_contracts()

        # await self.session_report.dump_report()
        await self.session_report.calculate()

    async def log_entry(self, address, key, eth_balance, asset_symbol, contract_addr=None, tok_bal=0.0):
        self.report_dict[address] = {'private_key': key, 'eth': eth_balance,
                                     'address': address,
                                     'tokens': [{'contract': contract_addr, 'symbol': asset_symbol, 'balance': tok_bal}]}

        async with aiofiles.open(self.outfile, 'w') as f:
            await f.write(json.dumps(self.report_dict))


def divide_chunks(l: list, n: int):
    for i in range(0, len(l), n):
        yield l[i:i + n]


ACCTS = []
from_key = web3.eth.Account.from_key


class KeyLoader:
    def __init__(self):
        self.keys = []
        self.accts = []
        self.printer = style.PrettyText()

    def parse_mnemonic(self, m):
        try:
            acct = Acct(None, m)
        except ValueError:
            pass
        else:
            return acct.__dict__

    def parse_key(self, k):
        try:
            acct = Acct(k)
        except (binascii.Error, ValueError):
            pass
        else:
            return acct.__dict__

    @staticmethod
    def sort_uniq(sequence):
        return (x[0] for x in itertools.groupby(sorted(sequence)))

    def _parse_keys(self, batch):
        print(len(batch))
        s = time.time()
        for key in batch:
            acct = self.parse_key(key)
            self.accts.append(acct)
            # print(acct)
        elapsed = time.time() - s
        print('[+] Parsed batch in %s seconds, total: %s' % (elapsed, len(self.accts)))

        return self.accts

    def _parse_mnemonics(self, batch):
        print(len(batch))
        s = time.time()
        for key in batch:
            acct = self.parse_mnemonic(key)
            self.accts.append(acct)
            # print(acct)
        elapsed = time.time() - s
        print('[+] Parsed batch in %s seconds, total: %s' % (elapsed, len(self.accts)))
        return self.accts

    def key_loader(self, keyfile):
        with open(keyfile, 'r') as f:
            f = f.readlines()
        print(f'[+] Read {len(f)} lines')
        keys = f
        keys_ = self.sort_uniq(keys)
        [self.keys.append(x) for x in keys_]
        # [parse_key(k) for k in keys]
        print(f'[+] Loaded {len(self.keys)} unique keys')
        return self.keys

    async def parallel_map(self, fn, inputs, *args):
        results = [None] * len(inputs)

        async def worker(j, inp):
            results[j] = await trio_parallel.run_sync(fn, inp, *args)
            print(j, "done")

        async with trio.open_nursery() as nursery:
            for i, inp in enumerate(inputs):
                nursery.start_soon(worker, i, inp)

        return results

    def multiprocess_key_parser(self, keys):
        # t0 = trio.current_time()
        batch_size = math.floor(len(keys) / os.cpu_count()) + 1
        if len(self.keys) > batch_size:
            _batches = divide_chunks(self.keys, batch_size)
            batches = []
            for b in _batches:
                batches.append(b)
        else:
            _batches = [keys]
        print(f'[+] Batches: {len(batches)}')
        self.printer.normal('Processing keys ... ')
        # async with trio.open_nursery() as nursery:
        # Do CPU-bound work in parallel
        if args.keymode == 'key':
            return trio.run(self.parallel_map, self._parse_keys, batches)
        return trio.run(self.parallel_map, self._parse_mnemonics, batches)


if __name__ == '__main__':
    args = argparse.ArgumentParser()
    args.add_argument('-f', '--file', type=str, default=None,
                      help='List of private keys to load into memory.')
    args.add_argument('-p', '--load_pickled_keys', type=str, default=None,
                      help='Pickle file with keys to load to memory.')
    args.add_argument('-km', '--keymode', choices=['key', 'mnemonic'], default='key')
    args.add_argument('-D', '--dump_pickled_keys', action='store_true',
                      help='After reading keys, dump to pickle file for fast loading later.')
    args.add_argument('-o', '--output', type=str,
                      help='Where to log results, if not specified a file will be generated.')
    args.add_argument('-t', '--token', type=str, nargs='+', default=None, help='An ERC20 token to query balance for.')
    args.add_argument('-cb', '--call_batch', type=int, default=1024,
                      help='The number of addresses to send to the smart contract at a time.')
    args.add_argument('-fb', '--file_batch', type=int, default=1000,
                      help='The number of keys per process for key loading')
    args.add_argument('-N', '--nonce_check', action='store_true', help='Look for active accounts')
    args.add_argument('-m', '--max_nonce', type=int, default=0,
                      help='For finding hidden ethereum, the max amount of future nonces to calculate and check.')
    args.add_argument('-n', '--network', type=str, choices=['ethereum', 'binance', 'arbitrum',
                                                            'polygon', 'optimism'],
                      help='The network to scan these accounts on.')
    args.add_argument('-dm', '--dual_mode', action='store_true',
                      help='If only scanning 1 token, use this mode which uses dual contract to save time.')
    args.add_argument('-T', '--threads', type=int, default=4, help='The number of threads to use for async web3.')
    args.add_argument('-v', '--verbosity', action='count', default=0,
                      help='Increases the output verbosity.')

    args = args.parse_args()
    os.environ["ASYNC_W3"] = "1"
    os.environ["MULTICALL_PROCESSES"] = f"{args.threads}"
    tokens = []

    api = BlitzScan(args.network, args.token, args.output)
    key_loader = KeyLoader()
    if not args.load_pickled_keys:
        keys = key_loader.key_loader(args.file)
        # print(keys)
        # for batch in batches:
        # _accts = []
        multiprocessing.freeze_support()
        _accts = key_loader.multiprocess_key_parser(keys)
        # print(ACCTS)
        _accts_ = []
        accts = []
        [accts.extend(y) for y in _accts]
        _accts = accts
        print(f'[+] Loaded total: {len(_accts)}')

        if args.dump_pickled_keys:
            print('[+] Pickling keys ... ')
            print(len(_accts))
            account_list = []

            with open(f'pickled_keys/{args.file}_pickled', 'wb') as pf:
                pickle.dump(_accts, pf)
    else:
        print('Loading pickled keyfile ... ')
        with open(args.load_pickled_keys, 'rb') as pf:
            accounts = pickle.load(pf)
            # print(type(accounts))
            _accts = []
            for a in accounts:
                if a:
                    _acct = web3.eth.Account.from_key(a.get('key'))
                    _accts.append(_acct)
        accts = accounts
    # for acct in _accts:
    #    print(acct)
    # print(ACCTS)
    # time.sleep(5)

    api.accounts = accts
    # for token in args.token:
    if args.nonce_check:
        asyncio.run(api.start_nonce_loop())
    else:
        if args.dual_mode:
            asyncio.run(api.start_loop_calculate_contracts())  # print('Keys:')  # print(len(api.keys))
        else:
            asyncio.run(api.start_loop())
