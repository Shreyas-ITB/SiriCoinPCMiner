#Based on original SiriCoinPCMiner
import time, importlib, json, sha3, platform, cpuinfo, multiprocessing, psutil
from web3.auto import w3
from eth_account.account import Account
from eth_account.messages import encode_defunct
from colorama import Fore
from rich import print
from pypresence import Presence
import pypresence
import os, configparser
from time import sleep
from multiprocessing import Process, Queue

#NODE_ADDR = "https://siricoin-node-1.dynamic-dns.net:5005/"
NODE_ADDR = "http://195.3.223.9:5005/"

#notify all these nodes as soon as we found a valid block
#nodes_notify = ["http://138.197.181.206:5005/", "https://node-1.siricoin.tech:5006"]

SYSM = ("[cyan][SYSM][/cyan]")
NODEM = ("[cyan][NODEM][/cyan]")

# process worker
# id of process, number of processes, input, output, report Queues
def worker(id, num, i, o, r):
    ctx_proof = sha3.keccak_256()
    nonce = id
    target = 0
    tmp0 =0
    start = time.time()
    work_done = 0
    while True:
        
        if i.empty():
            # report every 5 s 
            if(time.time() > (start + 5)):
                start = time.time()
                r.put(work_done)
                work_done = 0
            # report or update after N cycles to limit io requests
            for x in range(100000):
                ctx_proof2 = ctx_proof.copy()
                ctx_proof2.update(nonce.to_bytes(8, "big"))
                bProof = ctx_proof2.digest()
                # found solution
                if (int.from_bytes(bProof, "big") < target):
                    text_proof = "0x" + bProof.hex()
                    o.put([text_proof , nonce])
                nonce += num
            work_done+=100000
        else:
            [base, tar] = i.get()
            ctx_proof = sha3.keccak_256()
            ctx_proof.update(base)
            ctx_proof.update(tmp0.to_bytes(24, "big"))
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

        self.send_url = NODE_ADDR + "send/rawtransaction/?tx="
        self.block_url = NODE_ADDR + "chain/miningInfo"
        self.accountInfo_url = NODE_ADDR + "accounts/accountInfo/" + self.acct.address
        self.balance_url = NODE_ADDR + "accounts/accountBalance/" + RewardsRecipient
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
            return f"{round(hashrate, 2)}H/s"
        elif hashrate < 1000000:
            return f"{round(hashrate/1000, 2)}kH/s"
        elif hashrate < 1000000000:
            return f"{round(hashrate/1000000, 2)}MH/s"
        elif hashrate < 1000000000000:
            return f"{round(hashrate/1000000000, 2)}GH/s"

  
    def multiMine(self, NUM_THREADS):
        strt = (f"[blue]Started mining for {self.rewardsRecipient}[/blue]")
        print(NODEM, strt)
        proof = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        self_lastBlock = ""
        int_target = 0
    
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
            workerstxt = (f"[magenta]WorkerProcesses : {NUM_THREADS}[/magenta]")
            print(NODEM, lstxt)
            print(NODEM, trgtxt)
            print(NODEM, difftxt)
            print(NODEM, timestamp)
            print(NODEM, workerstxt)
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
        while True:
            if(time.time()> start+20):
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
                    workerstxt = (f"[magenta]WorkerProcesses : {NUM_THREADS}[/magenta]")
                    print(NODEM, lstxt)
                    print(NODEM, trgtxt)
                    print(NODEM, difftxt)
                    print(NODEM, timestamp)
                    print(NODEM, workerstxt)
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
                hstr = (f"[green]Hashrate : {self.formatHashrate(((total) / (time.time() - start)))} Last {round(time.time() - start,2)} seconds[/green]")
                print(SYSM, hstr)
                start = time.time()    
                
            # check if any process found a result, and submit the block
            for o in outputs:
                if(not o.empty()):
                    [pr, non] = o.get()
                    self.nonce = non
                    proof = pr
                    self.submitBlock({"miningData" : {"miner": self.rewardsRecipient,"nonce": self.nonce,"difficulty": self.difficulty,"miningTarget": self.target,"proof": proof}, "parent": self.lastBlock,"messages": self.messages.hex(), "timestamp": self.timestamp, "son": "0000000000000000000000000000000000000000000000000000000000000000"})
                    print({"miningData" : {"miner": self.rewardsRecipient,"nonce": self.nonce,"difficulty": self.difficulty,"miningTarget": self.target,"proof": proof}, "parent": self.lastBlock,"messages": self.messages.hex(), "timestamp": self.timestamp, "son": "0000000000000000000000000000000000000000000000000000000000000000"})



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
            thread = config_local.userinfo["threads"]
            thrint = (int(thread))
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
            print("[blue]---------------------------- System ----------------------------[/blue]")
            print(f"[violet]OS: {platform.system(), platform.release()}[/violet]")
            cpumain = (cpuinfo.get_cpu_info()["brand_raw"])
            print(f"[violet]CPU: {cpumain}[/violet]")
            print(f"[violet]CPUFamily: {platform.processor()}[/violet]")
            print(f"[violet]CPUThreads: {multiprocessing.cpu_count()}[/violet]")
            print(f"[violet]RAM: {round(psutil.virtual_memory().total / 1000000000, 2)}GB[/violet]")
            print(f"[violet]GPU: {platform.machine()}[/violet]")
            print(f"[blue]-----------------------------------------------------------------[/blue]") # code by luketherock868
            print("")
            rpc.update(state="Becoming Richer every day!", details="Mining SiriCoin with my CPU(s)", large_image="smallimage", small_image="logo", start=time.time())
            print("[green]Successfully Established Discord RPC..[/green]")
            miner = SiriCoinMiner(usraddr)
            miner.multiMine(thrint)
        except pypresence.exceptions.DiscordNotFound or pypresence.exceptions.DiscordError:
                print("[red]Couldnt Start Discord RPC Proceeding...[/red]")
                #Read config
                open("Config\config.ini", "r")
                print("[green]Got Config Data from the ConfigFiles.. Proceeding Further..[/green]")
                config_local = ConfigFile();
                config_local.read()
                usraddr = config_local.userinfo["walletaddr"]
                thread = config_local.userinfo["threads"]
                thrint = (int(thread))
                minead = (f"[blue]{usraddr}[/blue]")
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
                print("[blue]---------------------------- System ----------------------------[/blue]")
                print(f"[blue]OS: {platform.system(), platform.release()}[/blue]")
                cpumain = (cpuinfo.get_cpu_info()["brand_raw"])
                print(f"[blue]CPU: {cpumain}[/blue]")
                print(f"[blue]CPUFamily: {platform.processor()}[/blue]")
                print(f"[blue]CPUThreads: {multiprocessing.cpu_count()}[/blue]")
                print(f"[blue]RAM: {round(psutil.virtual_memory().total / 1000000000, 2)}GB[/blue]")
                print(f"[blue]GPU: {platform.machine()}[/blue]")
                print(f"[blue]-----------------------------------------------------------------[/blue]") 
                print("")
                miner = SiriCoinMiner(usraddr)
                miner.multiMine(thrint)
    if (not os.path.exists("Config\config.ini")):
            print("[red]No Config file found. Creating a new one in ConfigDir..[/red]")
            if not os.path.exists('Config'):
                os.makedirs('Config')
            config_local = ConfigFile();
            config_local.read()
            wallinpt = input("Please enter your SiriCoin wallet address: ")
            sleep(1)
            prntcpthr = (f"[blue]{multiprocessing.cpu_count()}[/blue]")
            print(f"[yellow]Number of threads present in your CPU: {prntcpthr} If you use more than that it could harm your CPU[/yellow]")
            thrinpt = input("Please enter the number of threads you want to use: ")
            if (wallinpt != "" ):
                config_local.userinfo["walletaddr"] = wallinpt
            if (thrinpt != ""):
                config_local.userinfo["threads"] = thrinpt    
            config_local.write()
            print("[green]Config Saved Successfully..[/green]")
            sleep(2)
            print("[red]Please Restart/Rerun the miner to continue..[/red]")
            exit()
