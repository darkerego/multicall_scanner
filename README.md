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

##### Usage

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
Install the requirements.txt like you normally would. Note that you may have to slightly 
modify the file `multicall.py` from the pypi `multicall` library. Simple find the function  
 __call__(self) and make it asynchronous like:
</p>

<pre>
async def __call__(self) -> Dict[str,Any]:
    start = time()
    response = await self.coroutine()
    logger.debug(f"Multicall took {time() - start}s")
    return response
    
</pre>

<p>
Then you just need to set your RPC endpoints. Create a .env file and for each chain that you want 
to use, configure in .env like this (for example ethereum):
</p>

<pre>
ethereum_http_endpoint = https://ethereum.infura.io/xxxx
ethereum_ws_endpoint = wss://ethereum.infura.io/xxxx
</pre>

#### Example usage

#### Scanning for eth/token balances, (or some custom call)
<p>
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

</p>
<p>
If you wanted to scan a list of either private keys or public addresses to check their 
Ether balance on the Ethereum main network, you could run ... 
</p>
<pre>
$ python3 mcscan.py -f keys/sample.keys -o sample.out -n ethereum 
</pre>

<p>
If you also wanted to check those accounts for an ERC20 token balance, you could specify

<pre>
python3 mcscan.py -f keys/sample.keys -o sample.out.json --token 0xdAC17F958D2ee523a2206206994597C13D831ec7`

</pre>

<p>
You can also write your own custom call function. Just add it to `lib/multicalls.py`. I will 
update this readme with details on that soon.
</p>

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
Note: not super well tested but should work. Specify the max nonce to check contracts that have not 
been deployed yet by each address. It will first have to get the nonces of each account, which cannot 
be done via multicall, so it takes a bit. Afterwards though, it will fire off all the getBalance calls 
with multicall and if it finds a balance in any of the undeployed contract addresses, it will report it!

</p>



