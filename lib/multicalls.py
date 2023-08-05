import asyncio
import os

import dotenv
import eth_abi
# from lib.modules import *
import multicall
from multicall import constants
from lib import style
import web3
from aiohttp import ClientResponseError
from eth_typing import ChecksumAddress
from eth_utils import to_checksum_address
from multicall import Call

from web3 import Web3
from web3.exceptions import ContractLogicError

import nest_asyncio
nest_asyncio.apply()

constants.MULTICALL3_ADDRESSES

class CallFailedError(Exception):
    pass


class MultiCalls:
    def __init__(self, rpcs: list, chain: str, http_fallback: bool = False):
        # self.arb_contract = contract
        self.chain = chain
        self.http_fallback = http_fallback
        # self.w3_arr = cycle(w3_arr)
        self.mc_addr = None
        self.calls = []
        # self.bal_con = bal_con
        self.param_dict = {}
        self.rpcs = rpcs
        self._w3: (web3.Web3, None) = None
        self.printer = style.PrettyText()

    async def __ainit__(self):
        dotenv.load_dotenv()
        self.create_dirs()
        await self.reconnect_ws()


    def create_dirs(self):
        try:
            os.mkdir('reports')
        except FileExistsError:
            pass


    async def reconnect_ws(self):
        # print('[~] Connecting to ', self.rpcs)
        RPC = None
        if not self.http_fallback:
            for rpc in self.rpcs:
                if rpc is not None:
                    if 'ws' in rpc:
                        self._w3 = Web3(web3.WebsocketProvider(rpc))
                        if self._w3.is_connected:
                            break
        if not RPC:
            for rpc in self.rpcs:
                if rpc is not None:
                    if 'http' in rpc:
                        self._w3 = Web3(web3.HTTPProvider(rpc))
                        if self._w3.is_connected:
                            break
        if not self._w3:
            self.printer.error(f'Unable to set up web3 for chain {self.chain}')
            exit(1)
        if not self._w3.is_connected:
            self.printer.error(f'Unable to set up web3 with endpoints: {self.rpcs}')
            exit(1)
        # web3.py got a badly implemented upgrade (just use @property next time!)
        if hasattr(self._w3, 'isConnected'):
            if self._w3.isConnected():
                self.printer.good(f'Connected to {self._w3.eth.chain_id}')
        else:
            if self._w3.is_connected():
                self.printer.good(f'Connected to {self._w3.eth.chain_id}')
        # print(f'[+] Contract configured with contract: {self.bal_con}')
        mc = multicall.Multicall(calls=[], _w3=self.w3, gas_limit=50000000000)
        self.mc_addr = mc.multicall_address

    def reset(self):
        self.calls.clear()

    @property
    def w3(self) -> Web3:
        return self._w3

    def add_custom_call(self, contract_address: str, input_array: list, output_array: list):
        r"^[a-zA-Z_]\w*\(((?:\w+\[\])|(?:\w+)|())(?:,\s*((?:\w+\[\])|(?:\w+)))*\)\(\((\w+),(\w+)\)\)$"
        assert (to_checksum_address(contract_address))
        assert (len(input_array) and type(input_array[0] is str))
        assert (len(output_array) == 1 and type(output_array[0] is str))
        _output_array = [(output_array[0], self.done_callback)]
        return multicall.Call(to_checksum_address(contract_address), input_array, _output_array)

    def add_call_builtin_balance(self, address: ChecksumAddress):
        call = multicall.Call(to_checksum_address(self.mc_addr),
                              ['getEthBalance(address)((uint256))', address],
                              [(address, self.done_callback)])
        return call

    def add_call_get_erc20_balance(self, address: ChecksumAddress, contract_address: ChecksumAddress):
        call = multicall.Call(to_checksum_address(contract_address),
                              ['balanceOf(address)((uint256))', address],
                              [(f'{address}_{contract_address}', self.done_callback)])
        # self.calls.append(call)
        return call

    def add_call_get_pair(self, factory: ChecksumAddress, token1: ChecksumAddress, token2: ChecksumAddress):
        call = multicall.Call(to_checksum_address(factory),
                              ['getPair(address,address)((address))', token1, token2],
                              [(f'{factory}_{token1}_{token2}', self.done_callback)])
        # self.calls.append(call)
        return call

    @staticmethod
    def done_callback(value: any):
        return value

    async def run(self, calls: list[Call]):
        assert calls
        asyncio.set_event_loop(asyncio.new_event_loop())
        # print(calls)
        ret = None
        sleeper = 1.5
        # print(self.calls)
        for x in range(3):
            if not calls:
                calls = self.calls
            else:
                calls = calls
            mc = multicall.Multicall(calls=calls, _w3=self.w3, gas_limit=100000000000)
            # print(type(mc))

            try:
                ret = mc()
                if asyncio.iscoroutine(ret):
                    ret = await ret

            except ClientResponseError as err:
                self.printer.error(f'multicall failed with chain {self.chain} with {err}! Try {x + 1}/3')
                sleeper += sleeper
                await asyncio.sleep(sleeper)
            except ContractLogicError as err:
                self.printer.error(f'Multicall Failed with chain {self.chain}: {err}!')
                sleeper += sleeper
                await asyncio.sleep(sleeper)
            except eth_abi.exceptions.EncodingTypeError as err:
                self.printer.error(f'Error: {err}')
            except ValueError as err:
                self.printer.error('Unknown Error with chain %s: %s , try reducing call batch size?' % (self.chain, err))
                sleeper += sleeper
            else:
                break
        # self.reset()
        if not ret:
            raise CallFailedError
        return ret
