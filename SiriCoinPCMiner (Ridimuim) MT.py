#Based on original SiriCoinPCMiner
import time, importlib, json, sha3
from web3.auto import w3
from eth_account.account import Account
from eth_account.messages import encode_defunct
from colorama import Fore
import multiprocessing 

n_threads = 4

#NodeAddr = "https://siricoin-node-1.dynamic-dns.net:5005/"
NodeAddr = "http://138.197.181.206:5005/"

class SignatureManager(object):
    def __init__(self):
        self.verified = 0
        self.signed = 0

    def signTransaction(self, private_key, transaction):
        message = encode_defunct(text=transaction["data"])
        transaction["hash"] = w3.soliditySha3(["string"], [transaction["data"]]).hex()
        _signature = w3.eth.account.sign_message(message, private_key=private_key).signature.hex()
        signer = w3.eth.account.recover_message(message, signature=_signature)
        sender = w3.toChecksumAddress(json.loads(transaction["data"])["from"])
        if (signer == sender):
            transaction["sig"] = _signature
            self.signed += 1
        return transaction

    def verifyTransaction(self, transaction):
        message = encode_defunct(text=transaction["data"])
        _hash = w3.soliditySha3(["string"], [transaction["data"]]).hex()
        _hashInTransaction = transaction["hash"]
        signer = w3.eth.account.recover_message(message, signature=transaction["sig"])
        sender = w3.toChecksumAddress(json.loads(transaction["data"])["from"])
        result = ((signer == sender) and (_hash == _hashInTransaction))
        self.verified += int(result)
        return result

class SiriCoinMiner(object):
    def __init__(self, RewardsRecipient):
        self.requests = importlib.import_module("requests")
        self.signer = SignatureManager()

        self.difficulty = 1
        self.target = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        self.lastBlock = ""
        self.rewardsRecipient = w3.toChecksumAddress(RewardsRecipient)
        self.priv_key = w3.solidityKeccak(["string", "address"], ["SiriCoin Will go to MOON - Just a disposable key", self.rewardsRecipient])

        self.timestamp = 0
        self.nonce = 0
        self.acct = w3.eth.account.from_key(self.priv_key)
        self.messages = b"null"

        self.lastSentTx = ""
        self.balance = 0

        self.send_url = NodeAddr + "send/rawtransaction/?tx="
        self.block_url = NodeAddr + "chain/miningInfo"
        self.accountInfo_url = NodeAddr + "accounts/accountInfo/" + self.acct.address
        self.balance_url = NodeAddr + "accounts/accountBalance/" + RewardsRecipient
        self.refreshBlock()
        self.refreshAccountInfo()

    def printBalance(self):
        balance = 0
        try:
            info = self.requests.get(self.balance_url).json().get("result")
            balance = info["balance"]
        except:
            print("Error balance")
        print(f"Balance: {balance}")
                
    def refreshBlock(self):
        try:
            info = self.requests.get(self.block_url).json().get("result")
            self.target = info["target"]
            self.difficulty = info["difficulty"]
            self.lastBlock = info["lastBlockHash"]
        except:
            print("refreshBlock: error")
        self.timestamp = int(time.time())

    def refreshAccountInfo(self):
        try:
            temp_txs = self.requests.get(self.accountInfo_url).json().get("result")
            _txs = temp_txs.get("transactions")
            self.lastSentTx = _txs[len(_txs)-1]
            self.balance = temp_txs.get("balance")
        except:
            print("refreshAccountInfo: error")

    def submitBlock(self, blockData):
        txid = "None"
        self.refreshAccountInfo()
        data = json.dumps({"from": self.acct.address, "to": self.acct.address, "tokens": 0, "parent": self.lastSentTx, "blockData": blockData, "epoch": self.lastBlock, "type": 1})
        tx = {"data": data}
        tx = self.signer.signTransaction(self.priv_key, tx)
        try:
            f = open(blockData.get("miningData")["proof"], "w")
            f.write(f"{self.send_url}{json.dumps(tx).encode().hex()}")
            f.close();
        except:
            print("file write error")
        tmp_get = self.requests.get(f"{self.send_url}{json.dumps(tx).encode().hex()}")
        if (tmp_get.status_code != 500 ):
            txid = tmp_get.json().get("result")[0]
        print(f"{Fore.GREEN}TimeStamp: {self.timestamp}, Nonce: {self.nonce}")
        print(f"Mined block {blockData['miningData']['proof']}")
        print(f"Submitted in transaction {txid}")
        return txid

    def formatHashrate(self, hashrate):
        if hashrate < 1000:
            return f"{round(hashrate, 2)}H/s"
        elif hashrate < 1000000:
            return f"{round(hashrate/1000, 2)}kH/s"
        elif hashrate < 1000000000:
            return f"{round(hashrate/1000000, 2)}MH/s"
        elif hashrate < 1000000000000:
            return f"{round(hashrate/1000000000, 2)}GH/s"

    def startMining(self, nCore):
        print(f"{Fore.GREEN}Started mining for {self.rewardsRecipient}")
        self.printBalance()
        proof = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        self_lastBlock = ""
        int_target = 0
        while True:
            self.refreshBlock()
            if (self_lastBlock != self.lastBlock):
                self_lastBlock = self.lastBlock
                int_target = int(self.target, 16)
                print("")
                print(f"{Fore.YELLOW}lastBlock   : {self_lastBlock}")
                print(f"{Fore.YELLOW}target      : {self.target}")
                print(f"{Fore.YELLOW}difficulty  : {self.difficulty}")
            messagesHash = w3.keccak(self.messages)
            bRoot = w3.soliditySha3(["bytes32", "uint256", "bytes32","address"], [self.lastBlock, self.timestamp, messagesHash, self.rewardsRecipient])
            self.nonce = 0
            tmp0 = 0
            start_nonce = self.nonce
            ctx_proof = sha3.keccak_256()
            ctx_proof.update(bRoot)
            ctx_proof.update(tmp0.to_bytes(24, "big"))
            t0 = time.time()
            t1 = t0 + 20
            while (time.time() < t1):
                tp = time.time() + 5
                while (time.time() < tp):
                    self.nonce += 1
                    ctx_proof2 = ctx_proof.copy()
                    ctx_proof2.update(self.nonce.to_bytes(8, "big"))
                    bProof = ctx_proof2.digest()
                    if (int.from_bytes(bProof, "big") < int_target):
                        proof = "0x" + bProof.hex()
                        self.submitBlock({"miningData" : {"miner": self.rewardsRecipient,"nonce": self.nonce,"difficulty": self.difficulty,"miningTarget": self.target,"proof": proof}, "parent": self.lastBlock,"messages": self.messages.hex(), "timestamp": self.timestamp, "son": "0000000000000000000000000000000000000000000000000000000000000000"})
                        t1 = 0
                        break
                print(f"t{nCore}{Fore.YELLOW}Hashrate : {self.formatHashrate(((self.nonce - start_nonce) / (time.time() - t0)))} Last {round(time.time() - t0,2)} seconds ")

if __name__ == "__main__":
    minerAddr = input("Enter your SiriCoin address : ")
    if (n_threads > 0):
        miners = []
        processes = []
        for i in range(0,4):	
            m = SiriCoinMiner(minerAddr)
            miners.append(m)
            p = multiprocessing.Process(target=miners[i].startMining, args=(i,))
            processes.append(p)
            p.start()
    else:
        miner = SiriCoinMiner(minerAddr)
        miner.startMining(0)
