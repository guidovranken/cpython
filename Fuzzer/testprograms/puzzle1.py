def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) == 64:
        if FuzzerInput[0] == ord('a'):
            raise Exception('Fuzzer puzzle succeeded')
