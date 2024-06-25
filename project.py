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
            str(self.index) + str(self.prev_hash)+str(self.transactions))
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

        self._txs = []
        self._last_block = blockchain.get_latest_block()
        self.__private_key = dsa.generate_private_key(key_size=2048)

        # Derive the public key from the private key
        self._public_key = self.__private_key.public_key()
        self._public_key_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        self.__private_key_pem = self.__private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    def __verify_node(self,node):
        if self.is_valid_block(node.last_block):
            # this node is honest
            return True
        return False

    def is_valid_block(self, block):
        lastBlock = self._last_block
        if block.hash == calculate_hash(str(lastBlock.index+1)+ str(lastBlock.hash)+ str(self._txs)):
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
            
            self._last_block = block
            self._txs = []
            return True
        return False

    def recieve_tx(self, tx):
        if self.verify_transaction(tx):
            self._txs.append(tx)
            return True
        return False
    


class AuthorityNode(CryptoNode):

    def __init__(self):
        super().__init__()
        self._last_block = blockchain.get_latest_block()
        self._txs = []
        self.__private_key = dsa.generate_private_key(key_size=2048)

        # Derive the public key from the private key
        self._public_key = self.__private_key.public_key()
        self._public_key_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        self._private_key_pem = self.__private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    def mine_block(self):
        lastBlock = self._last_block
        if len(self._txs) == 0:
            return

        # Create new block
        hash_value = calculate_hash(str(lastBlock.index + 1)+str(lastBlock.hash)+ str(self._txs))
        # sign block
        sign = sign_block(self.__private_key,hash_value)
        # new_block = Block(lastBlock.index + 1, lastBlock.hash, self.txs,
        #     {'pk':self.public_key_pem,'sign':sign})
        blockchain.add_block(self._txs,{'pk':self._public_key_pem,'sign':sign})
        self.last_block = blockchain.get_latest_block()
        self.broadcast_block()
        for tx in self._txs:
            self.add_coins_toClient(tx['amount'],tx['receiver'],tx['sender'])
        self.txs = []
        
    def add_coins_toClient(self,amount,recieverAddr, senderAddr ):
        sender = clients[senderAddr]
        reciever = clients[recieverAddr]
        reciever.balance += amount
        sender.balance -= amount
    

    def broadcast_block(self):
        for addr in node_addrs:
            if self._public_key_pem != addr:  
                authorithy_nodes[addr].recieve_block(self._last_block)

    def broadcast_tx(self):
        for addr in node_addrs:
            if self._public_key_pem != addr:  
                authorithy_nodes[addr].recieve_tx(self._txs[len(self._txs)-1])

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
    addr = cn._public_key_pem
    node_addrs.append(addr)
    authorithy_nodes.setdefault(addr, cn)

for i in range(3):
    clients.setdefault(i,Client(i, 10))

currentMiner = authorithy_nodes[node_addrs[0]]
miner2 = authorithy_nodes[node_addrs[1]]
clients[0].send_transaction(1,6,currentMiner)
currentMiner.broadcast_tx()
currentMiner.mine_block()
print(clients[0].balance)
print(clients[1].balance)
print(currentMiner.txs)
print(miner2.txs)
# print(auth_nodes[2]['addr'])
# cl1 = Client(1, 20)
# cl1 = Client(1, 20)
# print(cr_node.get_pk_pem())
# print(auth_nodes[0].get_pk_pem())
# print(cr_node.get_pv_pem())
# print(auth_nodes[0].get_pv_pem())
