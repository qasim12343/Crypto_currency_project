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
        self.latest_block = None
        self._private_key = dsa.generate_private_key(key_size=2048)

        # Derive the public key from the private key
        self. public_key = self._private_key.public_key()

    # def get_pv_pem(self):
    #     private_key_PEM = self._private_key.private_bytes(
    #         encoding=serialization.Encoding.PEM,
    #         format=serialization.PrivateFormat.PKCS8,
    #         encryption_algorithm=serialization.NoEncryption()
    #     )
    #     return private_key_PEM

    def get_pk_pem(self):
        public_key_PEM = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_key_PEM

    def is_valid_block(self, block):
        if block.hash == calculate_hash(str(block.index), block.prev_hash, str(self.txs)):
            return True
        return False

    def verify_transaction(self, transaction):

        # Check sender's balance
        sender_balance = self.get_balance(transaction.sender)
        if sender_balance < transaction.amount:
            return False

        return True

    def get_balance(self, address):
        balance = 0

        for transaction in block["transactions"]:
            if transaction["sender"] == address:
                balance -= transaction["amount"]
            if transaction["recipient"] == address:
                balance += transaction["amount"]
        return balance

    def recieve_block(self, block):
        if validate_block():
            self.latest_block = block
            return True
        return False

    def recieve_tx(self, tx):
        if validate_transaction(tx):
            self.txs.append(tx)
            return True
        return False


class AuthorityNode(CryptoNode):

    def __init__(self):
        self.txs = []
        self._private_key = dsa.generate_private_key(key_size=2048)

        # Derive the public key from the private key
        self. public_key = self._private_key.public_key()

    def get_pv_pem(self):
        private_key_PEM = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return private_key_PEM

    def get_pk_pem(self):
        public_key_PEM = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_key_PEM

    def verify_transaction(self, transaction):
        # Check sender's balance
        sender_balance = self.get_balance(transaction.sender)
        if sender_balance < transaction.amount:
            return False
        return True

    def is_valid_block(self, block):
        if block.hash == calculate_hash(str(block.index), block.prev_hash, str(self.txs)):
            validator = block.validator
            if verify_block(validator['pk'], block.hash, validator['sign']):
                return True
        return False

    def mine_block(self, lastBlock):
        if len(self.txs) == 0:
            return

        # Create new block
        new_block = {
            "index": lastBlock.index + 1,
            "transactions": self.txs,
            "previous_hash": lastBlock.prev_hash
        }

        # Broadcast new block to other nodes
        broadcast_block(new_block, blockChain)

    def recieve_tx(self, tx):
        if self.verify_transaction(transaction):
            self.txs.append(tx)
            return
        return

    def recieve_block(self, block):
        if self.is_valid_block(block):
            self.latest_block = block
            return True
        return False

    def broadcast_block(self, block, auth_nodes):
        for node in auth_nodes:
            node.recieve_block(block)


class Client:
    def __init__(self, node_address, balance):
        self.node_address = node_address
        self.balance = balance

    def send_transaction(self, sender, recipient, amount, node):
        transaction = {
            "sender": self.node_address,
            "recipient": recipient,
            "amount": amount
        }
        node.recieve_tx(transaction)

    def recieve_transaction(self, tx):
        pass


bc = Blockchain()
cr_node = CryptoNode()
auth_nodes = list()
for i in range(4):
    node = AuthorityNode()
    auth_nodes.append({'addr': node.get_pk_pem(), 'node': node})

cleints = [{'addr': i, 'client': Client(i, 10)} for i in range(3)]
print(auth_nodes[2]['addr'])
# cl1 = Client(1, 20)
# cl1 = Client(1, 20)
# print(cr_node.get_pk_pem())
# print(auth_nodes[0].get_pk_pem())
# print(cr_node.get_pv_pem())
# print(auth_nodes[0].get_pv_pem())
