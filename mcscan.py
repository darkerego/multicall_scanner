#!/usr/bin/env python3
import argparse
import asyncio
import binascii
import builtins
import itertools
import json
import math
import multiprocessing
import os
import pickle
import pprint
import time
from asyncio.exceptions import TimeoutError
from decimal import Decimal
# from itertools import cycle
from typing import Any, Generator

import aiofiles
import dotenv
import hexbytes
import rlp
import tqdm.asyncio as tqdma
import trio
import trio_parallel
import web3
from eth_account.signers.local import LocalAccount
from eth_typing import ChecksumAddress
from eth_utils import keccak, to_checksum_address, to_bytes
from multicall import Call
# import nest_asyncio
# from web3 import Web3, HTTPProvider, WebsocketProvider
from web3.exceptions import ContractLogicError
from websockets.exceptions import ConnectionClosedError

from lib import abi_lib
from lib import style
from lib.default_networks import SUPPORTED_NETWORKS
from lib.mnemonics_utils import mnemonic_to_private_key
from lib.multi_network import MultiNetworkManager
# from tqdm import tqdm
from lib.multicalls import MultiCalls
from utils.parse_report import MultiCallScanReportParser
# import mnemonic
web3.Account.enable_unaudited_hdwallet_features()
from_mnemonic = web3.Account.from_mnemonic

# nest_asyncio.apply()
dotenv.load_dotenv()
ZERO_ADDRESS = to_checksum_address('0x' + '0' * 40)



# mnem = mnemonic.Mnemonic("english")


class ScanReport:
    def __init__(self, log_file: str = None, __networks: list[str] = []):
        self.log_file = log_file
        self.report_dict = {}
        self.time_stamp = time.time()
        self.networks = __networks

    def add_wallet(self, eth: (int, float, str, Decimal), key: (str, hexbytes.HexBytes),
                   address: (str, ChecksumAddress), chain: str):
        if self.report_dict.get(address):
            # address_entry = self.report_dict.get(address)
            # if address_entry.get(chain):
            #    self.report_dict[address][chain]['eth'] = eth
            # else:
            #    self.report_dict.update({address: {chain: {'private_key': key, 'eth': eth, 'tokens': []}}})
            self.report_dict.get(address).get('chains').get(chain).update({'eth': eth})
            # self.report_dict.update({address: {chain: {'private_key': key, 'eth': eth, 'tokens': []}}})
        # asyncio.create_task(self.dump_report())

    def update_native_balance(self, address: (str, ChecksumAddress), balance: (int, float, str, Decimal), chain: str):
        # print(self.report_dict.get(address))
        self.report_dict[address]['chains'][chain]['eth'] = balance

    def update_native_balance_of_ether_search(self, address: (str, ChecksumAddress),
                                              contract_address: (str, ChecksumAddress),
                                              balance: (int, float, str, Decimal), chain: str):
        entry = self.report_dict.get(address).get('chains').get(chain)
        entry.update({'contract_address': contract_address, 'balance': balance})
        # self.report_dict.update({address: {chain: }})

    def add_acct_obj(self, acct: dict):
        address = acct['address']
        # print(self.report_dict)
        if self.report_dict.get(address):
            return
        chain_dict = {}
        for chain in self.networks:
            chain_dict.update({chain: {'eth': 0, 'tokens': []}})
        if acct:
            self.report_dict.update({address: {}})
            self.report_dict.get(address).update({'account': acct})
            self.report_dict.get(address).update({'chains': chain_dict})
        # print(self.report_dict.get(address))

    def add_token(self, token_address: (str, ChecksumAddress), token_balance: (int, float, str, Decimal),
                  token_symbol: str,
                  address: (str, ChecksumAddress), chain: str):
        self.report_dict[address]['chains'][chain]['tokens'].append({'symbol': token_symbol,
                                                                     'balance': token_balance,
                                                                     'contract': token_address})
        # asyncio.create_task(self.dump_report())

    async def dump_report(self, obj: dict = None):
        async with aiofiles.open(f'reports/{self.log_file}_{self.time_stamp}.json', 'w') as f:
            if not obj:
                await f.write(json.dumps(self.report_dict))
            else:
                await f.write(json.dumps(obj))

    async def calculate(self):
        print('[+] Calculating ... ')
        report_dict = {}
        for address, value in self.report_dict.items():
            for key, _value in value.items():
                if key == 'account':
                    ACCOUNT = _value
                CHAINS = {}
                if key == 'chains':
                    chain_data = _value
                    for chain, cdata in chain_data.items():
                        if cdata.get('eth') > 0 or len(cdata.get('tokens')) > 0:
                            CHAINS.update({chain: cdata})
                if len(CHAINS):
                    report_dict.update({address: {}})
                    report_dict.get(address).update({'chains': CHAINS})
                    report_dict.get(address).update({'account': ACCOUNT})
        await self.dump_report(report_dict)


class Acct:
    def __init__(self, key: (str, hexbytes.HexBytes) = None, mnemonic: str = None, derivation_path: str = None,
                 index: int = 0):
        acct = None
        if key:
            acct = web3.Account.from_key(key.strip('\r\n'))
        else:
            if mnemonic:
                key = self.mnemonic_to_key(mnemonic, derivation_path, index)
                acct = web3.Account.from_key(key)
        if not acct:
            return

        self.key = acct.key.hex()
        self.address = acct.address
        if derivation_path:
            self.derivation_path = derivation_path
            self._dict = {
                'key': self.key,
                'address': self.address,
                'mnemonic': mnemonic,
                'derivation_path': derivation_path
            }
        else:
            self._dict = {
                'key': self.key,
                'address': self.address,
                'mnemonic': '',
                'derivation_path': ''
            }

    def mnemonic_to_key(self, mnemonic: str, derivation_path: str, index: int = 0):
        private_key = mnemonic_to_private_key(mnemonic, derivation_path, "", index)
        return binascii.hexlify(private_key).decode("utf-8")

    def __hash__(self):
        return id(self.address)

    def __eq__(self, other: LocalAccount):
        return id(self.address) == id(other.address)

    @property
    def __dict__(self):
        if hasattr(self, '_dict'):
            return self._dict


class CallFailedError(Exception):
    """
    Raised when Multicall fails.
    """
    pass


class LogicError(Exception):
    """
    If you see this error, there is a bug. Please contact me.
    """
    pass


class MulticallScanner:
    def __init__(self, _networks: list[str], _tokens: list = None, outfile: str = None, custom_config: str = None):
        self.initialized = False
        self.token_total = 0
        self.eth_total = 0
        self.custom_config = custom_config
        self.total_scanned = 0
        self.keys = []
        self.outfile = outfile
        self._connection = None
        self.networks = _networks
        self.acct_dict = {}
        self.report_dict = {}
        self.session_report = ScanReport(outfile, networks)
        # self.endpoint = os.environ.get(f'{network}_http_endpoint')
        # self.ws_endpoint = os.environ.get(f'{network}_ws_endpoint')
        self.printer = style.PrettyText()
        self.concurrent_tasks = 0
        # w3_arr = []

        self.tokens = _tokens
        self.now = time.time()
        self.token_map = {}

        self.accounts = []
        # self.reset_mc(network)
        self.hits = {}

        if not self.outfile:
            self.outfile = f'output/keyscan_{time.time()}.json'
        else:
            self.outfile = f'output/{outfile}_{time.time()}.json'

        self.mcm = MultiNetworkManager(self.networks)

    async def __ainit__(self):
        """
        async init
        :return:
        """
        await self.mcm.__ainit__()
        if self.tokens:
            for chain in self.networks:
                self.setup_erc20(chain)
        self.initialized = True

    def get_mc(self, chain: str) -> (MultiCalls, False):
        mcm: MultiCalls = self.mcm.get_mc(chain)
        if mcm:
            return mcm
        return False

    def get_connection(self, chain: str) -> (web3.Web3, False):
        mcm: MultiCalls = self.get_mc(chain)
        if mcm:
            return mcm.w3
        return False

    async def reconnect_ws(self, chain: str):
        mcm = self.get_mc(chain)
        await mcm.reconnect_ws()

    def divide_chunks(self, l: list, n: int) -> list:
        for i in range(0, len(l), n):
            yield l[i:i + n]

    def setup_erc20(self, chain: str):
        """
        Get token metadata
        :return:
        """
        connection = self.get_connection(chain)
        if not connection:
            self.printer.warning(f'w3 not configured for {chain}')
            return False

        self.printer.good('Getting token metadata ... ')
        print('[+] Tokens: ', self.tokens)
        if self.tokens:
            for _token in self.tokens:
                _token = to_checksum_address(_token)
                # for token in self.tokens:
                contract = connection.eth.contract(_token, abi=abi_lib.EIP20_ABI)
                # check if this token even exists on this chain
                try:
                    contract.functions.balanceOf(ZERO_ADDRESS).call()
                except web3.exceptions.BadFunctionCallOutput as err:
                    # print(f'[!] Token err {err}')
                    return False
                else:

                    try:
                        decimals = {'decimals': contract.functions.decimals().call()}
                    except ContractLogicError:
                        print('[!] Error: reverted getting decimals, default to 18')
                        decimals = {'decimals': 18}
                    try:
                        symbol = {'symbol': contract.functions.symbol().call()}
                    except ContractLogicError:
                        print('[!] Error: reverted getting symbol, default to UNKNOWN')
                        symbol = {'symbol': 'UNKNOWN'}
                    self.token_map[chain] = {}
                    self.token_map[chain][contract.address] = {}
                    self.token_map[chain][_token].update(decimals)
                    self.token_map[chain][_token].update(symbol)
            # print(self.token_map)

    def native_balance_single(self, account: LocalAccount, chain: str):
        connection = self.get_connection(chain)
        return connection.eth.get_balance(account.address)

    def get_nonce(self, account: dict, chain: str):
        connection = self.get_connection(chain)
        return connection.eth.get_transaction_count(account.get('address'))

    def tx_count(self, account: LocalAccount, chain: str):
        connection = self.get_connection(chain)
        return connection.eth.get_transaction_count(account.address)

    async def run_account(self, account: dict, chain: str):
        try:
            txc = self.get_nonce(account, chain)
        except ConnectionClosedError:
            await self.reconnect_ws(chain)
            return await self.run_account(account, chain)
        else:
            return txc

    def __find_key(self, addr: (str, ChecksumAddress)):
        ret = None
        current_ids = set(acct for acct in self.accounts)
        for cid in current_ids:
            if cid.address == addr:
                ret = cid.key.hex()
        if not ret:
            raise LogicError
        return ret

    @staticmethod
    def find_key(addr: str, kb: list):
        # print(kb)
        """
        Locate the key for an address
        :param addr:
        :param kb:
        :return:
        """
        for acct in kb:
            if acct:
                if acct['address'] == addr:
                    return acct

    def add_call_eth(self, address: (str, ChecksumAddress), chain: str):
        """
        Add eth balance call to queue
        :param address:
        :return:
        """
        mc: MultiCalls = self.get_mc(chain)
        mc.add_call_builtin_balance(address)

    def add_custom_call(self):
        pass

    def add_call_erc20(self, address: (str, ChecksumAddress), token: (str, ChecksumAddress), chain: str):
        """
        Add an erc20 token balance call to the queue
        :param address:
        :param token:
        :return:
        """
        mc = self.get_mc(chain)
        mc.add_call_get_erc20_balance(address, token)

    async def start_nonce_loop(self, chain: str):
        """
        Searches for hidden ether
        :return:
        """
        await self.__ainit__()

        progress = tqdma.tqdm(self.accounts)
        progress.desc = str({'Hits': len(self.hits)})
        contract_addresses = []

        for batch in progress.iterable:
            calls = []
            for acct___ in batch:
                if acct___:
                    # self.session_report.add_wallet(0, acct___['key'], acct___['address'])
                    nonce = self.get_nonce(acct___, chain)
                    for x in range(args.max_nonce):
                        contract_addresses.append(self._mk_contract_address(acct___.get('address'), nonce + x))

            # txc = await self.run_account(account)

            """if txc > 0:
                self.hits[account.address] = {'nonce': txc}
                progress.desc = str({'Hits': len(self.hits)})
                print(f'{account.address}: TXC: {txc}')"""
            mc = self.get_mc(chain)
            [calls.append(mc.add_call_builtin_balance(to_checksum_address(addr))) for addr in contract_addresses]
            # acct_batches = self.divide_chunks(contract_addresses, args.call_batch)
            # acct_batches = [z for z in acct_batches]
            batches = self.divide_chunks(calls, args.call_batch)
            batches = [xx for xx in batches]
            batches = tqdma.tqdm(batches)
            for call_batch, acct_batch in zip(batches.iterable, progress.iterable):
                # ret = await self.mc.run(calls=call_batch)
                # await self.parse_calls_single_mode(ret, acct_batch)
                await self.multicall_task(call_batch, acct_batch, chain)

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

    def compute_contract_address(self, address: (str, ChecksumAddress), nonce: int):
        """
        Compute a contract address deterministically using an address and nonce.
        :param address:
        :param nonce:
        :return:
        """
        return to_checksum_address(self._mk_contract_address(to_checksum_address(address), nonce))

    async def logger(self, text):
        async with aiofiles.open(self.outfile, 'a') as ff:
            await ff.write(str(text + '\n'))

    async def w3_call(self, fn: any, *args: any, **kwargs: any):
        """
        Wrapper function to handle a web3 call
        :type fn: object
        :param fn:
        :param args:
        :param kwargs:
        :return:
        """
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

    async def parse_calls_single_mode(self, results: dict, kb: list, chain: str):
        """
        Parse the returned data
        :param results:
        :param kb:
        :return:
        """
        # find_key = self.find_key
        bal_str = 0.0
        eth_bal = 0.0
        tok_bal = 0
        tok_bal_str = 0
        for k, v in results.items():
            if not v:
                raise CallFailedError

            identifier = k.split('_')
            if len(identifier) == 1:
                wallet_addr = k
                token_addr = '0x0000000000000000000000000000000000000000'
                acct = self.find_key(wallet_addr, kb)
            else:
                wallet_addr, token_addr = identifier[0], identifier[1]
                acct = self.find_key(wallet_addr, kb)
            if token_addr == '0x0000000000000000000000000000000000000000':
                if v[0] > 0:
                    eth_bal = v[0] / (10 ** int(18))
                else:
                    eth_bal = 0.0
                bal_str = '{:f}'.format(eth_bal)
                # self.session_report.update_native_balance(wallet_addr, eth_bal)
                if eth_bal > 0:
                    if args.command == 'scan':
                        self.session_report.update_native_balance(wallet_addr, eth_bal, chain)
                    if args.command == 'etherSearch':
                        return eth_bal
                    # self.session_report.add_acct_obj(acct)

                self.eth_total += float(eth_bal)
            else:
                if self.token_map.get(chain).get(token_addr):
                    decimals = self.token_map[chain].get(token_addr).get('decimals')
                    symbol = self.token_map[chain].get(token_addr).get('symbol')
                    if v[0] > 0:
                        tok_bal = v[0] / 10 ** int(decimals)
                    else:
                        tok_bal = 0.0
                    tok_bal_str = '{:f}'.format(tok_bal)
                    if tok_bal > 0:
                        self.session_report.add_token(token_addr, tok_bal, symbol, wallet_addr, chain)
                        # self.session_report.add_acct_obj(acct)
                    # self.session_report.add_token(token_addr, tok_bal, symbol, wallet_addr)
                    self.token_total += float(tok_bal)
            if eth_bal > 0 or tok_bal > 0:
                pprint.pprint({'address': wallet_addr,
                               'chain': chain,
                               'balance': bal_str,
                               'token': {'address': token_addr,
                                         'key': acct['key'],
                                         'balance': tok_bal_str}})

    async def parse_calls(self, results: dict, kb: list, chain: str):
        """
        Parse the returned data

        :param results:
        :param kb:
        :return:
        """
        self.printer.normal('Parsing returned data for chain %s ... ' % chain)
        # for token in self.token_map:
        if args.custom_call:
            for k, v in results.items():
                if v[0] > 0:
                    # print(k, v)
                    await self.logger('%s:%s' % (k, v))
            return
        # if not args.dual_mode:
        return await self.parse_calls_single_mode(results, kb, chain)

    async def multicall_task(self, calls: list[Call], kb: list, chain: str):
        """
        Query contract for a batch of keys
        :param calls: calls to tryAggregate
        :param kb: keys
        :return:
        """
        # print(calls)
        self.concurrent_tasks += 1
        mc: MultiCalls = self.get_mc(chain)
        ret = await mc.run(calls=calls)
        # print(ret)
        self.concurrent_tasks -= 1
        # tokens = self.tokens

        asyncio.create_task(self.parse_calls(ret, kb, chain))

    async def start_loop_custom_call(self, input_array: list, output_array: list, chain: str):
        """
        Logic for handling a custom call
        :return:
        """
        # TODO: Finish implementing
        await self.__ainit__()
        if len(self.accounts) > args.call_batch:
            key_batches = self.divide_chunks(self.accounts, args.call_batch, )
        else:
            key_batches = [self.accounts]
        self.printer.normal(f'{len(self.accounts)} accounts in memory ...')
        # print(f'First acct: {self.accounts[0]}')
        # add_call_get_balance = self.mc.add_call_get_balance
        # add_call_get_erc20_balance = self.mc.add_call_get_erc20_balance

        # _find_key = self._find_key
        _find_key = self.__find_key
        # logger = self.logger
        _tot = int(len(self.accounts) / args.call_batch)
        progress = tqdma.tqdm(key_batches, total=_tot)
        # print(f'[~] Batches: {progress}')
        calls = []
        # tasks = set()
        mc: MultiCalls = self.get_mc(chain)
        for x, kb in enumerate(progress.iterable):
            for account in kb:
                if account:
                    addr = account.get('address')
                    # print(account.get('address'))
                    call = mc.add_custom_call(to_checksum_address(addr), input_array, output_array)
                    calls.append(call)
            # asyncio.create_task(self.multicall_task(calls))
            self.printer.normal('Sending batch request .. ')
            await asyncio.sleep(0.0001)
            # print(f'Adding batch. Batch %s/%s' %(x, _tot))
            await self.multicall_task(calls, kb, chain)
            calls = []
            mc.calls.clear()

        self.printer.good(f'Finished calls for {chain}')
        # await self.session_report.calculate()
        # await self.session_report.dump_report()

    async def start_loop_native(self, chain: str):

        # calls = []
        # print(len(self.accounts), args.call_batch)
        if len(self.accounts) > args.call_batch:
            total = len(self.accounts)
            self.printer.normal('Splitting keys into batches ... ')
            key_batches = self.divide_chunks(self.accounts, args.call_batch, )
        else:
            # print('Not splitting ... ')
            total = 0
            for _key_batch_ in self.accounts:
                for _key_ in _key_batch_:
                    total += 1
            key_batches = self.accounts
        self.printer.normal(f'Have {len(self.accounts)} batches in memory ...')
        self.printer.normal(f'Totaling {total} unique accounts ... ')

        # add_call_dual_balance = self.mc.add_call_dual_balance
        # _find_key = self._find_key
        _find_key = self.__find_key
        # logger = self.logger
        _tot = int(len(self.accounts) / args.call_batch)
        progress = tqdma.tqdm(key_batches, total=_tot)
        self.printer.normal(f'Batches: {progress}')
        calls = []
        # tasks = set()
        _tot = int(len(self.accounts) / args.call_batch)
        # progress = tqdm(key_batches, total=_tot)
        mc: MultiCalls = self.get_mc(chain)

        for x, kb in enumerate(progress.iterable):
            for account in kb:
                if not account:
                    pass
                else:
                    self.session_report.add_acct_obj(account)
                    # self.session_report.add_wallet(0, account['key'], account['address'], chain)
                if not account:
                    pass
                else:
                    if account:
                        # print(account)
                        addr = account.get('address')
                        # print(account.get('address'))
                        if not args.disable_native:
                            call = mc.add_call_builtin_balance(to_checksum_address(addr))
                            calls.append(call)
                        if self.tokens:
                            for contract_address in self.tokens:
                                tokens_chain = self.token_map.get('chain')
                                if tokens_chain:
                                    if tokens_chain.get(contract_address):
                                        # token_decimals = self.token_map.get(contract_address).get('decimals')
                                        # token_symbol = self.token_map[contract_address]['symbol']
                                        # print(f'[+] Processing token {token_symbol}')

                                        if account:
                                            addr = account['address']
                                            # print(account.get('address'))
                                            call = mc.add_call_get_erc20_balance(to_checksum_address(addr),
                                                                                 to_checksum_address(contract_address))
                                            calls.append(call)

            # asyncio.create_task(self.multicall_task(calls))
            self.printer.normal('Sending batch request .. ')
            await asyncio.sleep(0.0001)
            # print(f'Adding batch. Batch %s/%s' %(x, _tot))
            await self.multicall_task(calls, kb, chain)
            calls = []
            mc.calls.clear()

            # progress.set_postfix_str("Total %s: %s Total ETH: %s Concurrency: %s" % (
            #    token_symbol, self.token_total, self.eth_total, self.concurrent_tasks))
        self.printer.good('Finished calls')

    async def start_loop(self):
        if not self.initialized:
            await self.__ainit__()

        if args.command == 'etherSearch':
            tasks = set()
            # loop.run_until_complete(api.start_nonce_loop())
            for network in self.networks:
                self.printer.normal(f'Running chain {network}')
                await self.start_nonce_loop(network)
                # tasks.add(asyncio.create_task(self.start_nonce_loop(chain=network)))
        if args.command == 'scan':
            tasks = set()
            # loop.run_until_complete(api.start_loop_native())
            for network in self.networks:
                if network != 'all':
                    self.printer.normal(f'Creating task for {network}')
                    # await self.start_loop_native(network)
                    tasks.add(asyncio.create_task(self.start_loop_native(network)))
            await asyncio.gather(*tasks)

        await self.post_calculate()

    async def post_calculate(self):

        await self.session_report.calculate()
        # await self.session_report.dump_report()

    async def log_entry(self, address: str, key: str, eth_balance: float, asset_symbol: str,
                        contract_addr: (str, ChecksumAddress) = None, tok_bal: float = 0.0):
        """
        Log results
        :param address: eth acct address
        :param key: private key
        :param eth_balance:
        :param asset_symbol:
        :param contract_addr:
        :param tok_bal:
        :return:
        """
        self.report_dict[address] = {'private_key': key, 'eth': eth_balance,
                                     'address': address,
                                     'tokens': [
                                         {'contract': contract_addr, 'symbol': asset_symbol, 'balance': tok_bal}]}

        async with aiofiles.open(self.outfile, 'w') as f:
            await f.write(json.dumps(self.report_dict))


def divide_chunks(l: list, n: int):
    """
    Split a list into lists of lists
    :param l:
    :param n:
    :return: generator
    """
    for i in range(0, len(l), n):
        yield l[i:i + n]


ACCTS = []
from_key = web3.Account.from_key


class KeyLoader:
    def __init__(self):
        self.keys = []
        self.accts = []
        self.printer = style.PrettyText()

    def parse_mnemonic(self, m: str, derivation_path: str = None, index: int = 0):
        """
        Parse a single mnemonic
        :param m:
        :param derivation_path:
        :param index: index of child key
        :return:
        """
        # print(derivation_path)
        try:
            acct = Acct(None, m, derivation_path, index)
        except ValueError as err:
            print('[!] Error parsing mnemonic: ', err)
        else:
            return acct.__dict__

    def parse_key(self, k: (str, hexbytes.HexBytes)) -> dict:
        """
        Parse a single key
        :param k:
        :return:
        """
        try:
            acct = Acct(k)
        except (binascii.Error, ValueError):
            pass
        else:
            return acct.__dict__

    @staticmethod
    def sort_uniq(sequence: list) -> Generator[Any, Any, None]:
        return (x[0] for x in itertools.groupby(sorted(sequence)))

    def _parse_keys(self, batch: list) -> list:
        """
        Parse a batch of keys
        :param batch:
        :return:
        """
        self.printer.normal(f"Processing batch of {len(batch)} keys in a new process ...  ")
        s = time.time()
        for key in batch:
            acct = self.parse_key(key)
            self.accts.append(acct)
            # print(acct)
        elapsed = time.time() - s
        self.printer.normal('Processed batch in %s seconds, total: %s' % (elapsed, len(self.accts)))

        return self.accts

    def _parse_mnemonics(self, batch: list, derivation_path: str) -> list:
        """
        Generates keys from mnemonics
        :param batch: batch of keys
        :param derivation_path: path
        :return:
        """
        self.printer.normal(f"Processing batch of {len(batch)} mnemonics in a new process ...  ")
        # print(len(batch))
        s = time.time()
        for key in batch:
            for x in range(0, 5):
                acct = self.parse_mnemonic(key, derivation_path, index=x)
                self.accts.append(acct)
            # print(acct)
        elapsed = time.time() - s
        self.printer.normal('Parsed batch in %s seconds, total: %s' % (elapsed, len(self.accts)))
        return self.accts

    def key_loader(self, keyfile: str) -> list:
        """
        Load a list of keys from a file
        :param keyfile:
        :return:
        """
        with open(keyfile, 'r') as f:
            f = f.readlines()
        self.printer.normal(f'Read {len(f)} lines')
        keys_ = self.sort_uniq(f)
        [self.keys.append(x) for x in keys_]
        self.printer.normal(f'Loaded {len(self.keys)} unique keys')
        return self.keys

    async def parallel_map(self, fn: builtins.classmethod, inputs: any, *args: any):
        """
        Fires up trio-parallel so that we can bypass the
        global interpretter lock and make use of all of
        our available cpu cores.
        :param fn: function to call
        :param inputs: list of keys
        :param args: arguments to fn
        :return: None
        """
        results = [None] * len(inputs)

        async def worker(j: int, inp: any):
            results[j] = await trio_parallel.run_sync(fn, inp, *args)

        async with trio.open_nursery() as nursery:
            for i, inp in enumerate(inputs):
                nursery.start_soon(worker, i, inp)

        return results

    def multiprocess_key_parser(self, keys: list, derivation_path: str = None) -> list:
        """
        Wrapper around parallel_map
        :param keys: list of keys or mnemonics
        :param derivation_path: for mnemonics
        :return: list of account objects
        """
        # t0 = trio.current_time()
        batch_size = math.floor(len(keys) / os.cpu_count()) + 1
        if len(self.keys) > batch_size:
            _batches = divide_chunks(self.keys, batch_size)
            batches = []
            for b in _batches:
                batches.append(b)
        else:
            batches = [keys]
        self.printer.normal(f'Batches: {len(batches)}')
        self.printer.normal('Processing keys ... ')
        # async with trio.open_nursery() as nursery:
        # Do CPU-bound work in parallel
        if args.keymode == 'key':
            return trio.run(self.parallel_map, self._parse_keys, batches)
        return trio.run(self.parallel_map, self._parse_mnemonics, batches, derivation_path)


def pickle_dump(file: str):
    """
    Dump a list to file so that it can be
    quickly loaded later with pickle_load
    :param file: file to write
    :return: None
    """
    with open(file, 'wb') as pf:
        pickle.dump(eth_accounts, pf)


def pickle_load(file: str) -> list:
    """
    Load keys from pickle file
    :param file:
    :return:
    """
    with open(file, 'rb') as pf:
        _accounts = pickle.load(pf)
        # print(type(accounts))
        __accts = []
        for a in _accounts:
            if a:
                _acct = web3.Account.from_key(a.get('key'))
                __accts.append(_acct)
    return __accts


def read_as_lines(file) -> list:
    """
    Return stripped lines
    :param file: input file
    :return: list(lines)
    """
    with open(file, 'r') as f:
        return [line.strip('\r\n') for line in f.readlines()]


def post_process(_keys: list, derivation_path: str = None) -> list:
    """
    Mnemonic parsing
    """
    print('[+] Derivation path: %s' % derivation_path)
    return key_loader.multiprocess_key_parser(_keys, derivation_path)


def main(eth_accounts: list):
    """
    Sync program entry
    :param eth_accounts:
    :return:
    """
    api.accounts = eth_accounts
    # for token in args.token:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
    loop.run_until_complete(api.start_loop())


if __name__ == '__main__':
    args = argparse.ArgumentParser()
    # args.parse_known_intermixed_args()
    # args.add_argument('-f', '--file', type=str, default=None,
    #                   help='List of private keys to load into memory.')
    args.add_argument('-nc', '--check-children', dest='check_index_to', type=int, default=3)
    args.add_argument('-CC', '--custom-call', dest='custom_call', action='store_true')

    args.add_argument('-ia', '--input_array', type=list, help='Input array for custom call.')
    args.add_argument('-oa', '--output_array', type=list, help='Output array for custom call.')

    args.add_argument('-cb', '--call_batch', type=int, default=1024,
                      help='The number of addresses to send to the smart contract at a time.')
    args.add_argument('-fb', '--file_batch', type=int, default=1000,
                      help='The number of keys per process for key loading')
    # args.add_argument('-N', '--nonce_check', action='store_true', help='Look for active accounts')
    args.add_argument('-km', '--keymode', choices=['key', 'mnemonic'], default='key')

    args.add_argument('-n', '--networks', type=str, choices=SUPPORTED_NETWORKS, nargs='+',
                      default=None,
                      help='The network to scan these accounts on.')
    # args.add_argument('-T', '--threads', type=int, default=4, help='The number of threads to use for async web3.')
    args.add_argument('-v', '--verbosity', action='count', default=0,
                      help='Increases the output verbosity.')
    subparsers = args.add_subparsers(dest='command')
    scan = subparsers.add_parser('scan', help='Scan balances.')
    scan.add_argument('file', type=str, default=None, help='List of private keys, mnemonics, or public addresses.')
    scan.add_argument('-o', '--output', type=str,
                      help='Where to log results, if not specified a file will be generated.')
    scan.add_argument('-dn', '--disable-native', dest='disable_native', action='store_true',
                      help='Disable native balance calls.')
    scan.add_argument('-t', '--token', type=str, nargs='+', default=None,
                      help='An ERC20 token to query balance for. May be specified multiple times.')
    scan.add_argument('-bp', '--brute-paths', dest='brute_paths', type=str,
                      default=None, help='Load this list of derivation path and brute force the mnemonics.')

    ether_search = subparsers.add_parser('etherSearch', help='Searches for ether hidden in not-yet-generated '
                                                             'contracts.')
    ether_search.add_argument('file', type=str, default=None,
                              help='List of private keys, mnemonics, or public addresses.')
    ether_search.add_argument('-m', '--max_nonce', type=int, default=100,
                              help='For finding hidden ethereum, the max amount of future nonces to calculate and check.')
    ether_search.add_argument('-o', '--output', type=str,
                              help='Where to log results, if not specified a file will be generated.')

    parse = subparsers.add_parser('parse', help='Parse a previously generated report.')
    parse.add_argument('report_file', type=str)
    parse.add_argument('-t', '--threshold', type=float, default=0.0)
    parse.add_argument('-c', '--chain', type=str, default='ethereum')
    parse.add_argument('-d', '--debug', action='store_true')

    args = args.parse_args()
    os.environ["ASYNC_W3"] = "1"
    os.environ["MULTICALL_PROCESSES"] = f"{os.cpu_count()}"
    tokens = []
    PATHS = []
    if args.command == 'parse':
        rep_parser = MultiCallScanReportParser(args.report_file, args.debug)
        rep_parser.parse_report(args.chain, args.threshold)
        exit()
    if args.command == 'scan':
        if args.brute_paths:
            PATHS = read_as_lines(args.brute_paths)
            print(f'[+] Loaded {len(PATHS)} derivation PATHS')
        tokens = []
        if args.token:
            for token in args.token:
                try:
                    tokens.append(to_checksum_address(token))
                except (ValueError, binascii.Error):
                    print(f'[!] Invalid token address: {token}')
        print(f'[+] Specified {len(tokens)} tokens')

    networks = args.networks
    if args.networks == ['all'] or args.networks is None:
        networks = SUPPORTED_NETWORKS
    else:
        networks = args.networks
    print('[~] Networks: %s' % networks)
    if hasattr(args, 'output'):
        output_file = args.output
    else:
        output_file = f'no_name_{time.time()}'
    api = MulticallScanner(networks, tokens, output_file)
    key_loader = KeyLoader()
    keys = key_loader.key_loader(args.file)
    # print(keys)
    # all_accts = []
    eth_accounts = post_process(keys, "m/44'/60'/0'/0")
    all_accts = eth_accounts
    print(f'[+] Loaded total: {len(eth_accounts)}')
    if args.command == 'scan':
        if args.brute_paths:
            for path in PATHS:
                multiprocessing.freeze_support()
                eth_accounts = post_process(keys, path.strip('\r\n'))
                [all_accts.append(a) for a in eth_accounts]
            print(f'[~] Total to scan: {len(all_accts)}')



    main(all_accts)
