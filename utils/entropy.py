import math

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    freq = {}
    for b in data:
        freq[b] = freq.get(b, 1) + 1

    length = len(data)
    entropy = 0

    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 4)
