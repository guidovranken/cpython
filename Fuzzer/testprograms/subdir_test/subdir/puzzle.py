# Simple puzzle to test fuzzer efficacy

def run(inp):
    if len(inp) == 64:
        if inp[0] == ord('a'):
            raise Exception('Fuzzer puzzle succeeded')
