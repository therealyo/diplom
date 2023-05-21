# import sys
import os
import argparse

from dotenv import load_dotenv
load_dotenv()

from utils.data_collection import DataService
from analyzer.analyzer import Analyzer

def init_argparser():
    parser = argparse.ArgumentParser(description='RC4 Analyzer')
    parser.add_argument('--cached', metavar="filename", help="file to store and retrieve data from")
    parser.add_argument("--samples", metavar="num_samples", help="number of samples to generate")
    parser.add_argument("--visualize", action='store_true')
    return parser

if __name__ == "__main__":
    try: 
        parser = init_argparser()
        args = parser.parse_args()

        key = os.getenv("KEY")
        if isinstance(key, str):
            key = bytes(key, "utf-8")
        # print(args)
        # key = bytes("rc4encryption", "utf-8")  # 13 bytes

        data_service = DataService(key, args.cached)
        print("GENERATED KEY: ", data_service.key)

        if len(data_service.ciphers) == 0:
            num_samples = args.samples if args.samples else 100000

            data_service.generate_ciphers(num_samples)
            
        analyzer = Analyzer(data_service, args.visualize)
        retrieved_key = analyzer.attack()
        print("RETRIEVED KEY: ", retrieved_key)
        
    except Exception as e:
        print(e)


    # print(collector.ciphertexts)
