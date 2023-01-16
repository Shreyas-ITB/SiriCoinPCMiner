import time, json, platform, cpuinfo, multiprocessing, psutil, mock, secrets, requests

from web3.auto import w3
from eth_account.messages import encode_defunct

from rich import print
from rich.console import Console
from rich.table import Table
import pypresence

import os, configparser
from multiprocessing import Process, Queue, Event

import groestlcoin_hash, skein


#Miner config
miner_config = mock.Mock()
miner_config.nodes = ["http://78.58.45.205:5000", "http://madzcoin-58263.portmap.io:58263", "http://node.shming.us:5005"]
miner_config.coin = {"name": "MadzCoin", "ticker": "MADZ"}
miner_config.discord_id = 1061719628839137350 #Do not change to your discord user ID
miner_config.version = 0.1.1
miner_config.explorer_addr_URL = "http://madzcoin-explorer.aj.do/Explorer-testnet/address.html?address="

splash_screen = """                                                                                    
 _|      _|                    _|                _|_|_|              _|             
 _|_|  _|_|     _|_|_|     _|_|_|   _|_|_|_|   _|           _|_|          _|_|_|    
 _|  _|  _|   _|    _|   _|    _|       _|     _|         _|    _|   _|   _|    _|  
 _|      _|   _|    _|   _|    _|     _|       _|         _|    _|   _|   _|    _|  
 _|      _|     _|_|_|     _|_|_|   _|_|_|_|     _|_|_|     _|_|     _|   _|    _|  
                                                                                    
                                                                                     """
splash_screen_color = "bright_green"



def rgbPrint(string, color, end="\n"):
    print("[" + color + "]" + str(string) + "[/" + color + "]", end=end)

def Get_address():
    address_valid = False
    while not address_valid:
            minerAddr = input(f"Enter your {miner_config.coin['name']} address: ")
            try:
                address_valid = w3.isAddress(minerAddr)
            except:
                rgbPrint("The address you inputed is invalid, please try again", "red")
            if not address_valid:
                rgbPrint("The address you inputed is invalid, please try again", "red")
            else:
                return minerAddr
            
def pick_node(nodes):
    latency = {}

    for node in nodes:
        if node[-1] == "/": node = node[1:-1] #Remove / @ the end if it exists
        try:
            if requests.get(node + "/ping").json()["success"]:
                latency[node] = requests.get(node + "/ping").elapsed.microseconds
        except:
            pass

    return min(latency, key=latency.get)


console = Console()
def hashrate_table_update(queue, stop):

    data = queue.get()
    if type(data) == str:
        refreshed_data = data

    balance = "Unknown"
    blocks_n = "0"

    while not stop.is_set():
        with console.status(refreshed_data, spinner="dots", spinner_style="cyan") as status:
            while queue.empty():
                if not type(refreshed_data) == str:
                    refreshed_data.title = f"[green]Hit blocks: {blocks_n}[/green], [yellow]Balance: {balance}[/yellow], Runtime: {'{0:.2f}'.format(time.process_time())}s, [link={miner_config.explorer_addr_URL}]Explorer[/link]"
            
            data = queue.get()
            if type(data) == str:
                refreshed_data = data

            elif type(data) == dict:
                if "table" in data:
                    refreshed_data = data["table"]
                if "balance" in data:
                    balance = data["balance"]
                if "blocks" in data:
                    blocks_n = data["blocks"]
            
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
                r.put([work_done, id, time.perf_counter() - start])
                start = time.perf_counter()
                work_done = 0
            # report or update after N cycles to limit io requests
            for x in range(10000):
                final_hash = bRoot_hasher.copy()
                final_hash.update(nonce.to_bytes(32, "big"))
                bProof = groestlcoin_hash.getHash(b"".join([final_hash.digest(), nonce.to_bytes(32, "big")]), 64)

                if int.from_bytes(bProof, "big") < target:
                    o.put(["0x" + bProof.hex() , nonce])
                nonce += num
            work_done+=10000
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
        self.config_file_name = "madzcoin/MT-Miner_config.ini"
        self.config_object = configparser.ConfigParser()
        self.cfg = {}
        
    
    def read(self):
        self.config_object["cfg"] = {"walletaddr": []}
        if not os.path.exists(self.config_file_name):
            self.write()
        self.config_object.read(self.config_file_name)            
        self.cfg = self.config_object["cfg"]
                
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
        if signer == sender:
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
    def __init__(self, miner_config):
        self.signer = SignatureManager()

        self.preferred_node = pick_node(miner_config.nodes)
        self.difficulty = 1
        self.target = "0x" + "f"*64
        self.lastBlock = ""
        self.rewardsRecipient = miner_config.wallet_addr
        self.priv_key = w3.solidityKeccak(["string", "address"], ["MadzCoin for the win!!! - Just a disposable key - " + secrets.token_hex(128), self.rewardsRecipient])

        self.timestamp = 0
        self.nonce = 0
        self.acct = w3.eth.account.from_key(self.priv_key)
        self.messages = b"null"

        self.lastSentTx = ""

        self.mined_blocks = 0

        self.refreshBlock()
        self.refreshAccountInfo()

        if miner_config.print_method == 0 and not miner_config.debug:
            self.stop = Event()
            self.hashrate_queue = Queue()
            self.hashrate_queue.put("Waiting for first hashrate report")
            self.hashrate_t = Process(target=hashrate_table_update, args=[self.hashrate_queue, self.stop])
            self.hashrate_t.start()

        
                
    def refreshBlock(self):
        info = requests.get(self.preferred_node + "/chain/miningInfo").json()["result"]
        self.target = info["target"]
        self.difficulty = info["difficulty"]
        self.lastBlock = info["lastBlockHash"]
        self.timestamp = int(time.time())

    def refreshAccountInfo(self):
        temp_txs = requests.get(self.preferred_node + "/accounts/accountInfo/" + self.rewardsRecipient).json()["result"]
        _txs = temp_txs.get("transactions")
        self.lastSentTx = _txs[len(_txs)-1]
        self.balance = temp_txs.get("balance")

    def submitBlock(self, blockData):
        txid = "None"
        self.refreshAccountInfo()
        data = json.dumps({"from": self.acct.address, "to": self.acct.address, "tokens": 0, "parent": self.lastSentTx, "blockData": blockData, "epoch": self.lastBlock, "type": 1})
        tx = {"data": data}
        tx = self.signer.signTransaction(self.priv_key, tx)

        response = requests.get(f"{self.preferred_node + '/send/rawtransaction/?tx='}{json.dumps(tx).encode().hex()}")
            
        if response.status_code != 500:
            txid = response.json().get("result")[0]

        self.mined_blocks +=1
        self.refreshAccountInfo()
        if miner_config.print_method == 0 and not miner_config.debug:
            self.hashrate_queue.put({"blocks": str(self.mined_blocks), "balance": f"{self.balance} {miner_config.coin['ticker']}"})
        return txid

    def formatHashrate(self, hashrate):
        if hashrate < 1000:
            return f"{'{0:.2f}'.format(hashrate)} H/s"
        elif hashrate < 1000000:
            return f"{'{0:.2f}'.format(hashrate/1000)} kH/s"
        elif hashrate < 1000000000:
            return f"{'{0:.2f}'.format(hashrate/1000000)} MH/s"
        elif hashrate < 1000000000000:
            return f"{'{0:.2f}'.format(hashrate/1000000000)} GH/s"

  
    def multiMine(self, NUM_THREADS):
        global miner_config

        hashrate_table = ""
        rgbPrint(f"Started mining for: {self.rewardsRecipient} on: {self.preferred_node} \n", "cyan")

        proof = "0x" + "f"*64
        self_lastBlock = ""
        int_target = 0
    
        self.refreshBlock()
        if self_lastBlock != self.lastBlock:
            self_lastBlock = self.lastBlock
            if miner_config.debug:

                if miner_config.print_method == 1:


                    node_report_table = Table(title=f"Node report")
                    node_report_table.add_column("name", style="magenta")
                    node_report_table.add_column("value", style="yellow")

                    node_report_table.add_row("Last block", self.lastBlock)
                    node_report_table.add_row("Target block", self.target)
                    node_report_table.add_row("Difficulty", diffformat(self.difficulty))
                    node_report_table.add_row("Node timestamp", str(self.timestamp))

                    print(node_report_table)


        int_target = int(self.target, 16)
        messagesHash = w3.keccak(self.messages)
        bRoot = w3.soliditySha3(["bytes32", "uint256", "bytes32","address"], [self.lastBlock, self.timestamp, messagesHash, self.rewardsRecipient])
        
        inputs, outputs, workers, reports = [], [], [], []
        
        #spawn and start processes
        for n in range(0, NUM_THREADS):    
            i, o, r = Queue(), Queue(), Queue()
            t = Process(target = worker,args =(n,NUM_THREADS, i, o, r))

            i.put([bRoot, int_target])
            t.daemon = True
            inputs.append(i)
            outputs.append(o)
            workers.append(t)
            reports.append(r)
            t.start()
        
        # main thread does reporting (30s) and block submission
        start = time.perf_counter()    
        while True:
            if time.perf_counter() > start + 30:
                self.refreshBlock()
                if self_lastBlock != self.lastBlock:
                    self_lastBlock = self.lastBlock

                    if miner_config.debug:
                        if miner_config.print_method == 1:


                            node_report_table = Table(title=f"Node report")
                            node_report_table.add_column("name", style="magenta")
                            node_report_table.add_column("value", style="yellow")

                            node_report_table.add_row("Last block", self.lastBlock)
                            node_report_table.add_row("Target block", self.target)
                            node_report_table.add_row("Difficulty", diffformat(self.difficulty))
                            node_report_table.add_row("Node timestamp", str(self.timestamp))
                
                            print(node_report_table)


                int_target = int(self.target, 16)
                messagesHash = w3.keccak(self.messages)
                bRoot = w3.soliditySha3(["bytes32", "uint256", "bytes32", "address"], [self.lastBlock, self.timestamp, messagesHash, self.rewardsRecipient])

                for i in inputs:
                    i.put([bRoot, int_target])                    
                total = 0
                thread_hashrates = {}
                for r in reports:
                    while not r.empty():
                        _r = r.get()

                        if _r[1] in thread_hashrates: 
                            thread_hashrates[_r[1]] = (thread_hashrates[_r[1]] + (_r[0] / _r[2])) / 2 #If multiple reports are sent, get the AVG. (Shouldn't impact the result much, and gives a real world understanding)
                        else: 
                            thread_hashrates[_r[1]] = _r[0] / _r[2]

                        total += _r[0]
                end = time.perf_counter()

                avg_thread_hashrate = sum(thread_hashrates.values()) / (len(thread_hashrates.values()))

                hashrate_table = Table(title=f"Last {round(end - start, 2)}s hashrate")
                hashrate_table.add_column("Thread", style="cyan")
                hashrate_table.add_column("Hashrate " + " "*15, style="magenta")
                hashrate_table.add_row("Total", self.formatHashrate(sum(thread_hashrates.values())))


                for thread in thread_hashrates.items():
                    if thread[1] > avg_thread_hashrate: table_row_style = "green"
                    elif thread[1] < avg_thread_hashrate: table_row_style = "red"

                    hashrate_table.add_row(str(thread[0]), self.formatHashrate(thread[1]), style=table_row_style)

                # print(hashrate_table)
                if miner_config.print_method == 0 and not miner_config.debug:
                    self.hashrate_queue.put({"table": hashrate_table, "balance":  f"{self.balance} {miner_config.coin['ticker']}"})
                elif miner_config.print_method == 1:
                    print(hashrate_table)
            
                if miner_config.discord_rpc:
                    rpc.update(state=f"Mining {miner_config.coin['ticker']} on " + cpuinfo.get_cpu_info()['brand_raw'].replace(' with Radeon Graphics', '') + "!", details="Hashrate: " + self.formatHashrate(sum(thread_hashrates.values())) + ", Network balance: " + str(self.balance) + f" {miner_config.coin['ticker']}", large_image="madzcoin") #.replace(' with Radeon Graphics', ''), some AMD CPU's have this, removed to avoid confusion , some AMD CPU's have this, removed to avoid confusion

                start = time.perf_counter()

                
            # check if any process found a result, and submit the block
            for o in outputs:
                if(not o.empty()):
                    [pr, non] = o.get()
                    self.nonce = non
                    proof = pr
                    self.submitBlock({"miningData" : {"miner": self.rewardsRecipient, "nonce": self.nonce, "difficulty": self.difficulty, "miningTarget": self.target, "proof": proof}, "parent": self.lastBlock, "messages": self.messages.hex(), "timestamp": self.timestamp, "son": "0"*64})
                    


if __name__ == "__main__":
    if os.path.exists("madzcoin/MT-Miner_config.ini"):

            config = ConfigFile()
            config.read()

            miner_config.wallet_addr = config.cfg["walletaddr"]
            miner_config.threads = int(config.cfg["threads"])
            miner_config.debug = config.cfg["debug"].lower() == 'true'
            miner_config.discord_rpc = config.cfg["discord_rpc"].lower() == 'true'
            miner_config.print_method = int(config.cfg["print_method"])

            print("")
            rgbPrint(splash_screen, splash_screen_color)
            print("")
            rgbPrint(f"{'-'*28} System {'-'*28}", "blue")
            rgbPrint(f"OS: {platform.system(), platform.release()}", "violet")
            rgbPrint(f"CPU: {cpuinfo.get_cpu_info()['brand_raw'].replace(' with Radeon Graphics', '')}", "violet") # .replace(' with Radeon Graphics', ''), some AMD CPU's have this, removed to avoid confusion
            rgbPrint(f"CPU Family: {platform.processor()}", "violet")
            rgbPrint(f"CPU Threads: {multiprocessing.cpu_count()}", "violet")
            rgbPrint(f"RAM: {round(psutil.virtual_memory().total / 1073737400, 2)} GB", "violet")
            rgbPrint("-"*65, "blue")
            print("")

            if miner_config.discord_rpc:
                try:
                    rpc = pypresence.Presence(str(miner_config.discord_id))
                    rpc.connect()
                    rpc.update(state=f"Mining {miner_config.coin['ticker']} on " + cpuinfo.get_cpu_info()['brand_raw'].replace(' with Radeon Graphics', '') + "!", details="Hashrate: " + "Unknown" + ", Network balance: " + str(requests.get(f"{pick_node(miner_config.nodes)}/accounts/accountBalance/{miner_config.wallet_addr}").json()["result"]["balance"]) + f" {miner_config.coin['ticker']}", large_image="madzcoin", start=time.time()) #.replace(' with Radeon Graphics', ''), some AMD CPU's have this, removed to avoid confusion , some AMD CPU's have this, removed to avoid confusion
                except:
                    miner_config.discord_rpc = False
                    rgbPrint("Failed to establish Discord RPC", "red")
            
            miner = MadzCoinMiner(miner_config)
            miner.multiMine(miner_config.threads)

    else:
            rgbPrint("No config file found, creating a new one in the ``madzcoin`` directory...", "red")


            if not os.path.exists('madzcoin'): os.makedirs('madzcoin')
            config = ConfigFile()
            config.read()
            config.userinfo["walletaddr"] = Get_address()

            thread_inputed = False
            rgbPrint(f"Number of threads present in your CPU: {f'[blue]{multiprocessing.cpu_count()}[/blue]'}", "yellow")
            while not thread_inputed:
                thrinpt = input("\nPlease enter the number of threads you want to use: ")
                try:
                    config.userinfo["threads"] = str(int(thrinpt))
                    thread_inputed = True
                except:
                    rgbPrint("Invalid input!", "red")
            
            discord_rpc_inputed = False
            while not discord_rpc_inputed:
                discord_rpc = input("\nDo you want to use Discord RPC? (Y/Yes or N/No) ").lower()
                if discord_rpc == "y" or discord_rpc == "yes": config.userinfo["discord_rpc"] = "true"; discord_rpc_inputed = True
                elif discord_rpc == "n" or discord_rpc == "no": config.userinfo["discord_rpc"] = "false"; discord_rpc_inputed = True
                else: rgbPrint("Invalid input!", "red")

            debug_inputed = False
            while not debug_inputed:
                debug = input("\nDo you want to enable debug? (Recommended - N, you will lose features) (N/No or Y/Yes) ").lower()
                if debug == "y" or debug == "yes": config.userinfo["debug"] = "true"; debug_inputed = True; config.userinfo["print_method"] = "1"; print_method_inputed = True
                elif debug == "n" or debug == "no": config.userinfo["debug"] = "false"; debug_inputed = True
                else: rgbPrint("Invalid input!", "red")


            print_method_inputed = False
            while not print_method_inputed:
                print_method = input("\nWhich print method do you want to use? (0/1)\n0 - Recomended, updates a single table\n1 - re-prints the same table\n\n").lower()
                if print_method == "0" or print_method == "1": config.userinfo["print_method"] = str(print_method); print_method_inputed = True
                else: rgbPrint("Invalid input!", "red")

            config.write()          
            
            rgbPrint("\nConfig saved successfully, please restart the miner", "green")
            exit()
