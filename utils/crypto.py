import hashlib

def hash_ioc(data):
    return hashlib.sha256(data.encode()).hexdigest()

class MerkleTree:
    @staticmethod
    def store_root(data_blocks):
        hashes = [hashlib.sha256(x.encode()).hexdigest() for x in data_blocks]
        while len(hashes) > 1:
            hashes = [hashlib.sha256((hashes[i] + hashes[i+1]).encode()).hexdigest()
                      for i in range(0, len(hashes)-1, 2)]
        root = hashes[0]
        with open("merkle_root.txt", "w") as f:
            f.write(root)