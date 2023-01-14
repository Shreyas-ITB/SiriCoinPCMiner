#Based on original SiriCoinPCMiner.... Gonna have to rework it, it's full of BS.
import time, importlib, json, platform, cpuinfo, multiprocessing, psutil
from web3.auto import w3
from eth_account.messages import encode_defunct
from colorama import Fore
from rich import print
from pypresence import Presence
import pypresence
import os, configparser
from time import sleep
from multiprocessing import Process, Queue

import groestlcoin_hash, skein


NodeAddr = "http://madzcoin-58263.portmap.io:58263/"
nodes_notify = [NodeAddr]
miner_debug = True

SYSm = ("[cyan][SYSM][/cyan]")
NODEm = ("[cyan][NODEM][/cyan]")


def Get_address():
    address_valid = False


    while not address_valid:
            minerAddr = input("Enter your MadzCoin address: ")
            try:
                address_valid = w3.isAddress(minerAddr)
            except:
                print("[red]The address you inputed is invalid, please try again[/red]")
            if not address_valid:
                print("[red]The address you inputed is invalid, please try again[/red]")
            else:
                return minerAddr

# process worker
# id of process, number of processes, input, output, report Queues
def worker(id, num, i, o, r):
    bRoot_hasher = skein.skein256()
    nonce = id
    target = 0
    start = time.perf_counter()
    work_done = 0
    while True:
        
        if i.empty():
            # report every 5 s 
            if(time.perf_counter() > (start + 5)):
                start = time.perf_counter()
                r.put(work_done)
                work_done = 0
            # report or update after N cycles to limit io requests
            for x in range(100000):
                final_hash = bRoot_hasher.copy()
                final_hash.update(nonce.to_bytes(32, "big"))
                bProof = groestlcoin_hash.getHash(b"".join([final_hash.digest(), nonce.to_bytes(32, "big")]), 64)
                # found solution

                if (int.from_bytes(bProof, "big") < target):
                    text_proof = "0x" + bProof.hex()
                    o.put([text_proof , nonce])
                nonce += num
            work_done+=100000
        else:
            [base, tar] = i.get()
            bRoot_hasher = skein.skein256()
            bRoot_hasher.update(base)
            target = tar
            nonce = id


def diffformat(num):
    num = float('{:.3g}'.format(num))
    magnitude = 0
    while abs(num) >= 1000:
        magnitude += 1
        num /= 1000.0
    return '{}{}'.format('{:f}'.format(num).rstrip('0').rstrip('.'), ['', ' Thousand', ' Million', ' Billion', ' Trillion'][magnitude])

class ConfigFile(object):
    def __init__(self):
        self.config_file_name = "Config/config.ini"
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

class MadzCoinMiner(object):
    def __init__(self, RewardsRecipient):
        self.requests = importlib.import_module("requests")
        self.signer = SignatureManager()

        self.difficulty = 1
        self.target = "0x" + "f"*64
        self.lastBlock = ""
        self.rewardsRecipient = w3.toChecksumAddress(RewardsRecipient)
        self.priv_key = w3.solidityKeccak(["string", "address"], ["MadzCoin for the win!!! - Just a disposable key", self.rewardsRecipient])

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
            print("[red]Failed fetching balance[/red]")
            return 
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

        tmp_get = self.requests.get(f"{self.send_url}{json.dumps(tx).encode().hex()}")
        
        for node in nodes_notify:
            self.requests.get(f"{node}/send/rawtransaction/?tx={json.dumps(tx).encode().hex()}")
            
        if (tmp_get.status_code != 500 ):
            txid = tmp_get.json().get("result")[0]
        print(f"{Fore.GREEN}TimeStamp: {self.timestamp}, Nonce: {self.nonce}")
        print(f"Mined block {blockData['miningData']['proof']}")
        print(f"Submitted in transaction {txid}")
        return txid

    def formatHashrate(self, hashrate):
        if hashrate < 1000:
            return f"{round(hashrate, 2)} H/s"
        elif hashrate < 1000000:
            return f"{round(hashrate/1000, 2)} kH/s"
        elif hashrate < 1000000000:
            return f"{round(hashrate/1000000, 2)} MH/s"
        elif hashrate < 1000000000000:
            return f"{round(hashrate/1000000000, 2)} GH/s"

  
    def multiMine(self, NUM_THREADS):
        strt = (f"[blue]Started mining for {self.rewardsRecipient}[/blue]")
        print(NODEm, strt)
        proof = "0x" + "f"*64
        self_lastBlock = ""
        int_target = 0
    
        self.refreshBlock()
        if (self_lastBlock != self.lastBlock):
            self_lastBlock = self.lastBlock
            if miner_debug:
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
                workerstxt = (f"[magenta]WorkerProcesses : {NUM_THREADS}[/magenta]")
                print(NODEm, lstxt)
                print(NODEm, trgtxt)
                print(NODEm, difftxt)
                print(NODEm, timestamp)
                print(NODEm, workerstxt)
                self.printBalance()
                print("")
        int_target = int(self.target, 16)
        messagesHash = w3.keccak(self.messages)
        bRoot = w3.soliditySha3(["bytes32", "uint256", "bytes32","address"], [self.lastBlock, self.timestamp, messagesHash, self.rewardsRecipient])
        
        inputs = []
        outputs = []
        workers = []
        reports = []
        
        #spawn and start processes
        for n in range(0, NUM_THREADS):    
            i = Queue()
            o = Queue()        
            r = Queue()
            t = Process(target = worker,args =(n,NUM_THREADS, i, o, r))
            i.put([bRoot, int_target])
            t.daemon = True
            inputs.append(i)
            outputs.append(o)
            workers.append(t)
            reports.append(r)
            t.start()
        
        # main thread does reporting (20s) and block submission
        start = time.time()    
        hashing_start = time.perf_counter()
        while True:
            if(time.time()> start+20):
                self.refreshBlock()
                if (self_lastBlock != self.lastBlock):
                    self_lastBlock = self.lastBlock

                    lstblck = (f"[yellow]{self.lastBlock}[/yellow]")
                    trgt = (f"[yellow]{self.target}[/yellow]")
                    nonfrmtdiff = diffformat(self.difficulty)
                    diff = (f"[blue]{nonfrmtdiff}[/blue]")
                    serverts = (f"[yellow]{self.timestamp}[/yellow]")
                    lstxt = (f"[magenta]LastBlock : {lstblck}[/magenta]")
                    trgtxt = (f"[magenta]TargetBlock : {trgt}[/magenta]")
                    difftxt = (f"[magenta]CurrentDiff : {diff}[/magenta]")
                    timestamp = (f"[magenta]NodeTimeStamp : {serverts}[/magenta]")
                    workerstxt = (f"[magenta]WorkerProcesses : {NUM_THREADS}[/magenta]")
                    if miner_debug:
                        print("")
                        print(f"[green]Report[/green]")
                        print("")
                        print(NODEm, lstxt)
                        print(NODEm, trgtxt)
                        print(NODEm, difftxt)
                        print(NODEm, timestamp)
                        print(NODEm, workerstxt)
                    self.printBalance()
                    print("")
                int_target = int(self.target, 16)
                messagesHash = w3.keccak(self.messages)
                bRoot = w3.soliditySha3(["bytes32", "uint256", "bytes32","address"], [self.lastBlock, self.timestamp, messagesHash, self.rewardsRecipient])
        
                for i in inputs:
                    i.put([bRoot, int_target])                    
                total = 0
                for r in reports:
                    while not r.empty():
                        total += r.get()
                print(SYSm, "[green]Last " + str(round(time.perf_counter() - hashing_start, 2)) + "s hashrate: " + self.formatHashrate((total / (time.perf_counter() - hashing_start))) + "[/green]")
                rpc.update(state="Mining MADZ on " + cpuinfo.get_cpu_info()['brand_raw'] + "!", details="Hashrate: " + self.formatHashrate((total / (time.perf_counter() - hashing_start))) + ", Network balance: " + str(self.requests.get(self.balance_url).json()["result"]["balance"]) + " MADZ", large_image="madzcoin")
                start = time.time()  
                hashing_start = time.perf_counter() 
                
            # check if any process found a result, and submit the block
            for o in outputs:
                if(not o.empty()):
                    [pr, non] = o.get()
                    self.nonce = non
                    proof = pr
                    self.submitBlock({"miningData" : {"miner": self.rewardsRecipient,"nonce": self.nonce,"difficulty": self.difficulty,"miningTarget": self.target,"proof": proof}, "parent": self.lastBlock,"messages": self.messages.hex(), "timestamp": self.timestamp, "son": "0"*64})
                    if miner_debug: print({"miningData" : {"miner": self.rewardsRecipient,"nonce": self.nonce,"difficulty": self.difficulty,"miningTarget": self.target,"proof": proof}, "parent": self.lastBlock,"messages": self.messages.hex(), "timestamp": self.timestamp, "son": "0"*64})



if __name__ == "__main__":
    if (os.path.exists("Config/config.ini")):
            #Read config
            open("Config/config.ini", "r")
            print("[green]Parsed the config files... Proceeding Further...[/green]")
            config_local = ConfigFile()
            config_local.read()
            usraddr = config_local.userinfo["walletaddr"]
            thread = config_local.userinfo["threads"]
            thrint = (int(thread))
            print("")
            greeting = ("[green]Happy Mining![/green]")
            print(f"""[blue]
                            ______________________________
                            ||__________________________||
                            ||    MadzCoin PC Miner     || 
                            |____________________________|
                                {greeting}[/blue]""")
            print("")
            print("[blue]---------------------------- System ----------------------------[/blue]")
            print(f"[violet]OS: {platform.system(), platform.release()}[/violet]")
            cpumain = (cpuinfo.get_cpu_info()["brand_raw"])
            print(f"[violet]CPU: {cpumain}[/violet]")
            print(f"[violet]CPU Family: {platform.processor()}[/violet]")
            print(f"[violet]CPU Threads: {multiprocessing.cpu_count()}[/violet]")
            print(f"[violet]RAM: {round(psutil.virtual_memory().total / 1000000000, 2)}GB[/violet]")
            print(f"[blue]-----------------------------------------------------------------[/blue]") # code by luketherock868
            print("")

            try:
                rpc = Presence("1061719628839137350")
                rpc.connect()
                rpc.update(state="Mining MADZ on " + cpuinfo.get_cpu_info()['brand_raw'] + "!", details="Hashrate: " + "Unknown" + ", Network balance: " + str(importlib.import_module("requests").get(f"{NodeAddr}accounts/accountBalance/{usraddr}").json()["result"]["balance"]) + " MADZ", large_image="madzcoin", start=time.time())
                print("[green]Successfully established Discord RPC..[/green]")
            except:
                print("[red]Failed to stablish Discord RPC..[/red]")
            
            miner = MadzCoinMiner(usraddr)
            miner.multiMine(thrint)
    if (not os.path.exists("Config/config.ini")):
            print("[red]No config. file found, creating a new one in the ``Config`` directory...[/red]")
            if not os.path.exists('Config'):
                os.makedirs('Config')
            config_local = ConfigFile();
            config_local.read()
            wallinpt = Get_address()
            prntcpthr = (f"[blue]{multiprocessing.cpu_count()}[/blue]")
            print(f"[yellow]Number of threads present in your CPU: {prntcpthr}[/yellow]")
            thrinpt = input("Please enter the number of threads you want to use: ")
            if (wallinpt != "" ):
                config_local.userinfo["walletaddr"] = wallinpt
            if (thrinpt != ""):
                config_local.userinfo["threads"] = thrinpt    
            config_local.write()
            print("[green]Config saved successfully..[/green]")
            sleep(2)
            print("[red]Please restart the miner to continue..[/red]")
            exit()
