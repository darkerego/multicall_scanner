# Multicall Scanner

#### About
<p>
This is a tool that can run a contract call against a very large list of inputs. The contract call 
can (with a little bit of modification) be anything, but I was using it for obtaining balance information 
(either for native ethereum or of ERC20 tokens) across a large list of ethereum accounts. 
I am working on finishing implementing support for custom contract calls, but with a little modification you 
can easily modify this code to make any type of call that you need. 
Currently, native balance and ERC20 token balances are supported. There are also some other examples in 
the code, such as for obtaining liquidity pool reserves. The possible uses for this tool are only limited by 
your imagination.

</p>

###### Asciinema Demo
[![asciicast](https://asciinema.org/a/QOSaUu7kLOStynw84B9r0zkFj.svg)](https://asciinema.org/a/QOSaUu7kLOStynw84B9r0zkFj)


### Usage

<pre>
usage: mcscan.py [-h] [-cc CHECK_INDEX_TO] [-cC] [-ia INPUT_ARRAY] [-oa OUTPUT_ARRAY] [-cb CALL_BATCH] [-fb FILE_BATCH] [-km {key,mnemonic}]
                 [-n {ethereum,binance,arbitrum,polygon,optimism,aurora,xdai,heco,all} [{ethereum,binance,arbitrum,polygon,optimism,aurora,xdai,heco,all} ...]] [-v]
                 {scan,etherSearch} ...

positional arguments:
  {scan,etherSearch}
    scan                Scan balances.
    etherSearch         Searches for ether hidden in not-yet-generated contracts.

options:
  -h, --help            show this help message and exit
  -cc CHECK_INDEX_TO, --check-children CHECK_INDEX_TO
  -cC, --custom-call
  -ia INPUT_ARRAY, --input_array INPUT_ARRAY
                        Input array for custom call.
  -oa OUTPUT_ARRAY, --output_array OUTPUT_ARRAY
                        Output array for custom call.
  -cb CALL_BATCH, --call_batch CALL_BATCH
                        The number of addresses to send to the smart contract at a time.
  -fb FILE_BATCH, --file_batch FILE_BATCH
                        The number of keys per process for key loading
  -km {key,mnemonic}, --keymode {key,mnemonic}
  -n {ethereum,binance,arbitrum,polygon,optimism,aurora,xdai,heco,all} [{ethereum,binance,arbitrum,polygon,optimism,aurora,xdai,heco,all} ...], --networks {ethereum,binance,arbitrum,polygon,optimism,aurora,xdai,heco,all} [{ethereum,binance,arbitrum,polygon,optimism,aurora,xdai,heco,all} ...]
                        The network to scan these accounts on.
  -v, --verbosity       Increases the output verbosity.

</pre>


##### Uses Multicall Protocol

<p>
This scanner uses Multicall.py, which allows us to run up to 1024 calls at once (this is the max 
call depth of the EVM). 
</p>

##### Multicore Key Parser

<p>
In order to be able to load into a memory a very large list of ethereum keys, the program uses 
the `trio` library to bypass Python's global interpreter lock and utilize all available CPU 
cores while loading the keys into memory, which depending on your system can turn an operation 
that would have taken hours into a task that only takes perhaps 1 minute. 
</p>


#### Multi EVM Chain Support

<p>
The tool comes with support for the many chains out of box including (but not limited to):
</p>
 
- Ethereum
- Arbitrum
- Arbitrum Nova
- BSC
- Optimism
- Polygon
- Aurora

<p>
Any EVM compatible chain can theoretically work. The only requirement is that the multicall contract is deployed.
Here is a list of current deployments:

[Multicall Deployment Addresses by Network](https://github.com/banteg/multicall.py/blob/master/multicall/constants.py)

</p>

#### Installation and configuration

<p>
Install the requirements.txt like you normally would. It is possible/probable that you
will not have this issue, but ... Note that you **may** have to slightly 
modify the file `multicall.py` from the pypi `multicall` library... if you get an error about
the event loop already running, you just simply need to edit: 

`env/lib/python3.10/site-packages/multicall/multicall.py`  

Find the function  

 `def __call__(self)` 
 

and make it asynchronous like:


<pre>
    async def __call__(self) -> Dict[str,Any]:  # make it async
        start = time()
        response = await self  # instead of await_awaitable(self)
        logger.debug(f"Multicall took {time() - start}s")
        return response
    
</pre>

<p>
Then you just need to set your RPC endpoints. Create a .env file and for each chain that you want 
to use, configure in .env like this(in example, replacing `chain` with `ethereum`) :
</p>
<pre>
chain_http_endpoint
chain_ws_endpoint
</pre>

<p>
Example .env:
</p>

<pre>
ethereum_http_endpoint = https://ethereum.infura.io/xxxx
ethereum_ws_endpoint = wss://ethereum.infura.io/xxxx
arbitrum_http_endpoint =  https://arbitrum.infura.io/xxxx
arbitrum_ws_endpoint = wss://arbitrum.infura.io/xxxx
</pre>

<p>
Out of the box, the default networks that run (if you don't specify any via `--networks`), the following 
is the default (you can edit this to your liking in `lib/default_networks.py`) and you would need to configure 
RPCs for these networks:
</p>
<pre>
SUPPORTED_NETWORKS = ['ethereum', 'binance', 'arbitrum',
                      'polygon', 'optimism', 'aurora', 'xdai',
                      'heco', 'all']
</pre>

<p>
I am currently using ankr.com for all of my RPC's. It only costs $15 per month, and that's sufficient 
for a decent amount of scans. You can simply specify the networks you want to scan like:

`--networks ethereum arbitrum bsc`
</p>

#### Example usage

#### Scanning for eth/token balances, (or some custom contract cal [*] l)
<pre>
usage: mcscan.py scan [-h] [-o OUTPUT] [-dn] [-t TOKEN [TOKEN ...]] [-bp BRUTE_PATHS] file

positional arguments:
  file                  List of private keys, mnemonics, or public addresses.

options:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Where to log results, if not specified a file will be generated.
  -dn, --disable-native
                        Disable native balance calls.
  -t TOKEN [TOKEN ...], --token TOKEN [TOKEN ...]
                        An ERC20 token to query balance for. May be specified multiple times.
  -bp BRUTE_PATHS, --brute-paths BRUTE_PATHS
                        Load this list of derivation path and brute force the mnemonics.

</pre>
<p>
If you wanted to scan a list of either private keys or public addresses to check their 
Ether balance on the Ethereum main network, you could run ... 
</p>
<pre>
$ python3 mcscan.py -f keys/sample.keys -o sample.out -n ethereum 
</pre>

<p>
Keep in mind that sample list is just a few thousand publicly burned keys, and this program **really** 
shines when you are scanning tens of thousands, or millions of accounts. 
</p>

<p>
If you also wanted to check those accounts for an ERC20 token balance, you could specify

<pre>
python3 mcscan.py -f keys/sample.keys -o sample.out.json --token 0xdAC17F958D2ee523a2206206994597C13D831ec7`

</pre>

<p>

`* custom contract calls: `
You could easily write your own custom call function. Just add it to `lib/multicalls.py`. Currently, 
you could write a function for any contract call that took an address as it's only input. Perhaps 
future version of this program will have more versatile support for custom contract calls. I'd have to 
think about how best to implement it. However, if you are a programmer you can easily modify this 
to your data aggregation needs. For example, here's a function to get the reserves of a liquidity pool:
</p>

<pre>
    def add_call_get_reserves(self, pair_address: (str, ChecksumAddress)):
        
        return multicall.Call(pair_address, ['getReserves()((uint112,uint112,uint32))'],
                              [(pair_address, self.done_callback)])
        
</pre>

### Searching for hidden ether
<pre>
usage: mcscan.py etherSearch [-h] [-m MAX_NONCE] [-o OUTPUT] file

positional arguments:
  file                  List of private keys, mnemonics, or public addresses.

options:
  -h, --help            show this help message and exit
  -m MAX_NONCE, --max_nonce MAX_NONCE
                        For finding hidden ethereum, the max amount of future nonces to calculate and check.
  -o OUTPUT, --output OUTPUT
                        Where to log results, if not specified a file will be generated.

</pre>
<p>

**Note**: This is beta functionality. Specify the max nonce to check contracts that have not 
been deployed yet by each address. It will first have to get the nonces of each account, which cannot 
be done via multicall, so it takes a bit. Afterwards though, it will fire off all the getBalance calls 
with multicall and if it finds a balance in any of the undeployed contract addresses, it will report it!

</p>



