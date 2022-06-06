#Based on original SiriCoinPCMiner
import time, importlib, json, sha3
from web3.auto import w3
from eth_account.account import Account
from eth_account.messages import encode_defunct
from colorama import Fore
from rich import print
import pypresence
from pypresence import Presence
import os, configparser
from time import sleep

#NodeAddr = "https://siricoin-node-1.dynamic-dns.net:5005/"
NodeAddr = "http://138.197.181.206:5005/"

SYSm = ("[cyan][SYSM][/cyan]")
NODEm = ("[cyan][NODEM][/cyan]")

def diffformat(num):
    num = float('{:.3g}'.format(num))
    magnitude = 0
    while abs(num) >= 1000:
        magnitude += 1
        num /= 1000.0
    return '{}{}'.format('{:f}'.format(num).rstrip('0').rstrip('.'), ['', ' Thousand', ' Million', ' Billion', ' Trillion'][magnitude])

class ConfigFile(object):
    def __init__(self):
        self.config_file_name = "Config\config.ini"
        self.config_object = configparser.ConfigParser()
        self.userinfo = {}
    
    def read(self):
        self.config_object["USERINFO"] = { "walletaddr": []}
        if (os.path.exists(self.config_file_name) is False):
            self.write()
        self.config_object.read(self.config_file_name)            
        self.userinfo = self.config_object["USERINFO"]
                
    def write(self):
        with open(self.config_file_name, "w") as conf:
            self.config_object.write(conf)

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

    def startMining(self):
        strt = (f"[blue]Started mining for {self.rewardsRecipient}[/blue]")
        print(NODEm, strt)
        proof = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        self_lastBlock = ""
        int_target = 0
        while True:
            self.refreshBlock()
            if (self_lastBlock != self.lastBlock):
                self_lastBlock = self.lastBlock
                print("")
                print(f"[green]Node Report[/green]")
                print("")
                lstblck = (f"[yellow]{self.lastBlock}[/yellow]")
                trgt = (f"[yellow]{self.target}[/yellow]")
                nonfrmtdiff = diffformat(self.difficulty)
                diff = (f"[blue]{nonfrmtdiff}[/blue]")
                serverts = (f"[yellow]{self.timestamp}[/yellow]")
                lstxt = (f"[magenta]LastBlock : {lstblck}[/magenta]")
                trgtxt = (f"[magenta]TargetBlock : {trgt}[/magenta]")
                difftxt = (f"[magenta]CurrentDiff : {diff}[/magenta]")
                timestamp = (f"[magenta]NodeTimeStamp : {serverts}[/magenta]")
                print(NODEm, lstxt)
                print(NODEm, trgtxt)
                print(NODEm, difftxt)
                print(NODEm, timestamp)
                self.printBalance()
                print("")
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
                hstr = (f"[green]Hashrate : {self.formatHashrate(((self.nonce - start_nonce) / (time.time() - t0)))} Last {round(time.time() - t0,2)} seconds[/green]")
                print(SYSm, hstr)

if __name__ == "__main__":
    print("[yellow]Trying to start Discord RPC...[/yellow]")
    if (os.path.exists("Config\config.ini")):
        try:
            rpc = Presence("983430664357560400")
            rpc.connect()
            #Read config
            open("Config\config.ini", "r")
            print("[green]Got Config Data from the ConfigFiles.. Proceeding Further..[/green]")
            config_local = ConfigFile()
            config_local.read()
            usraddr = config_local.userinfo["walletaddr"]
            print("")
            greeting = ("[green]Happy Mining![/green]")
            print(f"""[blue]
                        ______________________________
                        ||__________________________||
                        ||    Siricoin PC Miner    || 
                        ||     By SiriCoin Team     ||
                        ||__________________________||
                        |____________________________|
                                {greeting}[/blue]""")
            print("")
            rpc.update(state="Becoming Richer every day!", details="Mining SiriCoin with my CPU(s)", large_image="smallimage", small_image="logo", start=time.time())
            print("[green]Successfully Established Discord RPC..[/green]")
            miner = SiriCoinMiner(usraddr)
            miner.startMining()
        except pypresence.exceptions.DiscordNotFound or pypresence.exceptions.DiscordError:
                print("[red]Couldnt Start Discord RPC Proceeding...[/red]")
                #Read config
                open("Config\config.ini", "r")
                print("[green]Got Config Data from the ConfigFiles.. Proceeding Further..[/green]")
                config_local = ConfigFile();
                config_local.read()
                usraddr = config_local.userinfo["walletaddr"]
                minead = (f"[blue]{usraddr}[/blue]")
                greeting = ("[green]Happy Mining![/green]")
                print(f"""[blue]
                ______________________________
                ||__________________________||
                ||    Siricoin AVR Miner    || 
                ||     By SiriCoin Team     ||
                ||__________________________||
                |____________________________|
                        {greeting}[/blue]""")
                print("")
                miner = SiriCoinMiner(usraddr)
                miner.startMining()
    if (not os.path.exists("Config\config.ini")):
            print("[red]No Config file found. Creating a new one in ConfigDir..[/red]")
            if not os.path.exists('Config'):
                os.makedirs('Config')
            config_local = ConfigFile();
            config_local.read()
            wallinpt = input("Please enter your SiriCoin wallet address: ")
            if (wallinpt != "" ):
                config_local.userinfo["walletaddr"] = wallinpt
            config_local.write()
            print("[green]Config Saved Successfully..[/green]")
            sleep(2)
            print("[red]Please Restart/Rerun the miner to continue..[/red]")
            exit()
