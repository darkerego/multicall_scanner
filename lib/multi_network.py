import web3
import dotenv
import os
from lib import multicalls
from lib import style


class MultiNetworkManager:

    def __init__(self, chains: list[str]):
        dotenv.load_dotenv()
        self.chains = chains
        if self.chains.__contains__('all'):
            for x, c in enumerate(self.chains):
                if c == 'all':
                    self.chains.pop(x)
        self.multicall_objects: dict = {}
        self.printer = style.PrettyText()
        self.a_initialized = False
        self.setup_all()

    async def __ainit__(self):
        for chain, mc in self.multicall_objects.items():
            # print('mc', mc)
            await mc.__ainit__()
        self.a_initialized = True

    def setup_all(self):
        self.printer.good('Attempting to configure multicall objects ... ')
        for chain in self.chains:
            mc_entry = {chain: self.setup_multicall(chain)}
            if mc_entry.get(chain):
                self.printer.good(f'MultiNetwork: Configured Multicalls for {chain}')
                self.multicall_objects.update(mc_entry)
            else:
                self.printer.warning(f'MultiNetwork: Could not configure Multicalls for {chain}')

    def setup_multicall(self, chain: str) -> (multicalls.MultiCalls, False):
        http_rpc = os.environ.get(f'{chain}_http_endpoint')
        ws_rpc = os.environ.get(f'{chain}_ws_endpoint')
        rpcs = [ws_rpc, http_rpc]
        mc = multicalls.MultiCalls(rpcs, chain)
        if mc:
            return mc
        return False

    def get_mc(self, chain: str) -> (multicalls.MultiCalls, False):
        obj = self.multicall_objects.get(chain)
        if obj:
            return obj
        return False

    def w3(self, chain: str) -> (web3.Web3, False):
        obj: multicalls.MultiCalls = self.get_mc(chain)
        if obj:
            return obj.w3
        return False
