import json
import os
import dotenv
import aiohttp


class PriceAgg:
    def __init__(self, network, scanner_obj):
        dotenv.load_dotenv()
        self.network = network
        self.scanner_obj = scanner_obj

    async def __ainit__(self):
        self._session = aiohttp.ClientSession()
        await self.get_base_fees()

    async def fetch(self, url: str, params: str = None):
        """
        aiohttp get
        :param url:
        :return:
        """

        print(f'[debug] Fetching: {url}')

        async with self._session.get(url, params=params) as response:
            resp = await response.read()
            stat = response.status
            # print("{}:{} with delay {}".format(date, resp, stat))
            # pprint.pprint(resp.decode())
            return stat, resp

    async def get_base_fees(self):
        """
        Get the ethereum network price and fee info
        :return:

        https: // api.bscscan.com / api
        ?module = stats
        & action = bnbprice
        & apikey = YourApiKeyToken

        """
        # print('Getting base fee')
        if self.network in ['ethereum', 'ETH']:
            s, r = await self.fetch(
                f'https://api.etherscan.io/api?module=gastracker&action=gasoracle&apikey={os.environ.get("etherscan_api_key")}')
            base_fee = json.loads(r.decode())
        elif self.network == 'polygon':
            from modules import polygon
            poly = polygon.PolygonMod()
            base_fee = poly.get_base_fee()

        else:
            s, r = await self.fetch(
                f'https://api.bscscan.com/api?module=gastracker&action=gasoracle&apikey={os.environ.get("bscan_api_key")}')
            base_fee = json.loads(r.decode())

        self.scanner_obj.base_fee = base_fee.get('result').get('SafeGasPrice')
        print(f'[+] Base Fee: {self.scanner_obj.base_fee}')
        if self.network.lower() in ['eth', 'ethereum']:
            s, r = await self.fetch(
                url=f'https://api.etherscan.io/api?module=stats&action=ethprice&apikey={os.environ.get("etherscan_api_key")}')
            eth_price = json.loads(r.decode())
            __price = eth_price.get('result').get('ethusd')
        elif self.network.lower() in ['polygon']:
            from modules import polygon
            poly = polygon.PolygonMod()
            __price = poly.get_matic_price()
        elif self.network.lower() in ['bsc', 'binance', 'bnb']:
            s, r = await self.fetch(
                f'https://api.bscscan.com/api?module=stats&action=bnbprice&apikey={os.environ.get("bscan_api_key")}')
            eth_price = json.loads(r.decode())
            __price = eth_price.get('result').get('ethusd')
        else:
            print(f'[!] Price agg: Warning: Unknown network: {self.network}, so we have no concept of price. You can set it manually with --eth_price')

        self.scanner_obj.eth_price = __price
        print(f'[+] Eth price: {self.scanner_obj.eth_price}, Base Fee: {self.scanner_obj.base_fee}')