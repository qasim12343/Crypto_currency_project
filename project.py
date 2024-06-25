import hashlib
import json
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.exceptions import InvalidSignature


def calculate_hash(value):
    data = value.encode()

    # Hash the data
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    hash_value = digest.finalize()
    return hash_value


def sign_block(private_key, hash_value):
    # Sign the data
    signature = private_key.sign(
        hash_value,
        Prehashed(hashes.SHA256())
    )
    return signature


def verify_block(public_key_pem, hash_value, signature):
    loaded_public_key = serialization.load_pem_public_key(public_key_pem)

    # Verify the signature
    try:
        loaded_public_key.verify(
            signature,
            hash_value,
            Prehashed(hashes.SHA256())
        )
        return True
    except InvalidSignature:
        return False


class Block:
    def __init__(self, index, prev_hash, transactions, validator):
        self.index = index
        self.prev_hash = prev_hash
        self.transactions = transactions
        self.hash = calculate_hash(
            str(self.index) + self.prev_hash+str(self.transactions))
        self.validator = validator


class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        return Block(0, "0", [],  None)

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, transactions, validator):
        prev_block = self.get_latest_block()
        prev_hash = prev_block.hash
        index = prev_block.index
        block = Block(index+1, prev_hash, transactions, validator)
        self.chain.append(block)


class CryptoNode:

    def __init__(self):

        self.txs = []
        self.last_block = Block(0,'0',[],None)
        self._private_key = dsa.generate_private_key(key_size=2048)

        # Derive the public key from the private key
        self. public_key = self._private_key.public_key()
        self.public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        self._private_key_pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    # def get_pv_pem(self):
    #     private_key_PEM = self._private_key.private_bytes(
    #         encoding=serialization.Encoding.PEM,
    #         format=serialization.PrivateFormat.PKCS8,
    #         encryption_algorithm=serialization.NoEncryption()
    #     )
    #     return private_key_PEM

    # def get_pk_pem(self):
    #     public_key_PEM = self.public_key.public_bytes(
    #         encoding=serialization.Encoding.PEM,
    #         format=serialization.PublicFormat.SubjectPublicKeyInfo
    #     )
    #     return public_key_PEM

    def is_valid_block(self, block):
        if block.hash == calculate_hash(str(block.index)+ block.prev_hash+ str(self.txs)):
            validator = block.validator
            if verify_block(validator['pk'], block.hash, validator['sign']):
                return True
        return False

    def verify_transaction(self, transaction):

        address = transaction['sender']
        sender_balance = clients[address].balance
        if sender_balance < transaction['amount']:
            return False
        return True

    def recieve_block(self, block):
        if self.is_valid_block(block):
            self.latest_block = block
            return True
        return False

    def recieve_tx(self, tx):
        if self.verify_transaction(tx):
            self.txs.append(tx)
            return True
        return False
    


class AuthorityNode(CryptoNode):

    def __init__(self):
        super().__init__()
        self.last_block = Block(0,'0',[],None)
        self.txs = []
        self._private_key = dsa.generate_private_key(key_size=2048)

        # Derive the public key from the private key
        self. public_key = self._private_key.public_key()
        self.public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        self._private_key_pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    def mine_block(self):
        lastBlock = self.latest_block
        if len(self.txs) == 0:
            return

        # Create new block
        hash_value = calculate_hash(str(lastBlock.index + 1)+lastBlock.prev_hash+ self.txs)
        # sign block
        sign = sign_block(self._private_key,hash_value)
        new_block = Block(lastBlock.index + 1, lastBlock.hash, self.txs,
            {'pk':self.public_key_pem,'sign':sign})
        self.last_block = new_block
        blockchain.add_block(self.txs,{'pk':self.public_key_pem,'sign':sign})
        self.broadcast_block()
        for tx in self.txs:
            self.add_coins_toClient(tx['amount'],tx['receiver'],tx['sender'])
        
    def add_coins_toClient(self,amount,recieverAddr, senderAddr ):
        sender = clients[senderAddr]
        reciever = clients[recieverAddr]
        reciever.balance += amount
        sender.balance -= amount
    

    def broadcast_block(self):
        for addr in node_addrs:
            if self.public_key_pem != addr:  
                authorithy_nodes[addr].recieve_block(self.latest_block)

    def broadcast_tx(self):
        for addr in node_addrs:
            if self.public_key_pem != addr:  
                authorithy_nodes[addr].recieve_tx(self.txs[len(self.txs)-1])

class Client:
    def __init__(self, node_address, balance):
        self.node_address = node_address
        self.balance = balance

    def send_transaction(self, recipient, amount, node):
        transaction = {
            "sender": self.node_address,
            "receiver": recipient,
            "amount": amount
        }
        node.recieve_tx(transaction)


blockchain = Blockchain()
cr_node = CryptoNode()
authorithy_nodes = {}
node_addrs = []
clients={}

for i in range(4):
    cn = AuthorityNode()
    addr = cn.public_key_pem
    node_addrs.append(addr)
    authorithy_nodes.setdefault(addr, cn)

for i in range(2):
    clients.setdefault(i,Client(i, 10))

currentMiner = authorithy_nodes[node_addrs[0]]
miner2 = authorithy_nodes[node_addrs[1]]
clients[0].send_transaction(1,10,currentMiner)
currentMiner.broadcast_tx()
# print(clients[0].balance)
print(currentMiner.txs)
print(miner2.txs)
# print(auth_nodes[2]['addr'])
# cl1 = Client(1, 20)
# cl1 = Client(1, 20)
# print(cr_node.get_pk_pem())
# print(auth_nodes[0].get_pk_pem())
# print(cr_node.get_pv_pem())
# print(auth_nodes[0].get_pv_pem())
