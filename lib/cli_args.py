import argparse


def get_args():
    args = argparse.ArgumentParser('EVilM Toolkit')
    args.add_argument('-f', '--file', type=str, default=None, help='Input file with keys/addresses')
    # args.add_argument('-ts', '--targets', default=[])
    args.add_argument('-a', '--address', type=str, default=None, help='Single address to scan')
    args.add_argument('-S', '--seek_to', type=int, default=0, help='Seek to batch')
    args.add_argument('-s', '--session', type=str, help='Load a scan session file')
    args.add_argument('-dp', '--derivation_path', default=None)
    args.add_argument('-e', '--ens', action='store_true')
    args.add_argument('-c', '--chain', type=str, default='okc', choices=['BTC', 'BCH', 'ETH', 'OKC',
                                                                         'BSC', 'ETC', 'LTC', 'DASH',
                                                                         'TRON', 'POLYGON', 'AVAXC',
                                                                         'APT', 'ETHW', 'ETHF', 'FTM',
                                                                         'OPTIMISM', 'ARBITRUM'])
    args.add_argument('-t', '--token_type', choices=['token_20', 'token_721'], default='token_20')
    args.add_argument('-d', '--disable_native', action='store_true', help='Don\'t scan native wallet.')
    args.add_argument('-b', '--batch', type=int, default=5)
    args.add_argument('-T', '--threshold', type=float, default=1.0,
                      help='Do not bother with assets of value lower than this.')
    args.add_argument('-o', '--output', type=str, default='scan')
    args.add_argument('-ep', '--eth_price', type=float, default=0,
                      help='Manually set the native asset price incase network not implemented in price aggregator.')
    args.add_argument('-C', '--contracts', action="store_true", help='Enable contract vulnerability scanner.')
    args.add_argument('-me', '--contract_min_eth_qty', type=float, default=0.1, help='Min eth to scan')
    args.add_argument('-v', '--verbose', action='count', default=0)
    args = args.parse_args()

    return args