import json

def FuzzerRunOne(FuzzerInput):
    try:
        l = json.loads(FuzzerInput)
        return bytes(json.dumps(l).encode())
    except:
        pass
