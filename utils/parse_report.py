#!/usr/bin/env python3

import json
import os
import pprint
import argparse
import lib.style as style


class MultiCallScanReportParser:
    def __init__(self, report: str, debug: bool = False):
        self.report_file = report
        self.printer = style.PrettyText()
        self.debug = debug
        self.report_data: dict = self.load_json(report, fail_exit=True)

    def debug_print(self, data: any):
        if self.debug:
            self.printer.warning((str(data)))

    def load_json(self, file: str, fail_exit=False) -> (dict, False):
        if not os.path.exists(file):
            self.printer.error(f'File: {file} does not exist')
            if not fail_exit:
                return False
            exit(1)
        self.debug_print(f'opening {file}')
        with open(file, 'r') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError as err:
                self.printer.error(f'Error parsing {file}: {err}')
                if not fail_exit:
                    return False
                exit(1)
            else:
                return data

    def parse_report(self, chain: str, eth_threshold: float = 0, out_file: str = None):
        final = {}
        self.debug_print(f'Options: Chain {chain}, Threshold: {eth_threshold}... ')
        for address, data in self.report_data.items():
            for key, value in data.items():
                if key == 'chains':
                    chains_data = data.get('chains')
                    for _chain, balance_data in chains_data.items():
                        if _chain == chain:
                            if balance_data.get('eth') >= eth_threshold:
                                final.update({address: data})
                                pprint.pprint(json.loads(json.dumps(data)))
        if out_file:
            with open(out_file, 'w') as f:
                json.dump(final, f)


def main():
    args = argparse.ArgumentParser()
    args.add_argument('report_file', type=str)
    args.add_argument('-t', '--threshold', type=float, default=0.0)
    args.add_argument('-c', '--chain', type=str, default='ethereum')
    args.add_argument('-o', '--output', type=str, default=None)
    args.add_argument('-d', '--debug', action='store_true')
    args = args.parse_args()
    rep_parser = MultiCallScanReportParser(args.report_file, args.debug)
    rep_parser.parse_report(args.chain, args.threshold, args.output)


if __name__ == '__main__':
    main()