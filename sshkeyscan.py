#!/usr/bin/python3

import ipaddress, socket, paramiko, hashlib, base64, sys, pprint, time, queue, threading, signal, pymongo, json, logging, logging.handlers

class SigHandler:

    stopper = None
    threads = None
    logger = logging.getLogger('sshkeyscan')

    def __init__(self, stop_evt, threads):
        self.stop_evt = stop_evt
        self.threads = threads

    def __call__(self, signum, frame):
        self.stop_evt.set()
        self.logger.info("sig received, waiting for threads to close conns...")
        for thread in self.threads:
            thread.join()
        self.logger.info("conns closed, exiting...")
        sys.exit(0)



class KeyFinder(threading.Thread):

    target_q = None
    stop_evt = None
    retry_count = None
    timeout = None
    mc = pymongo.MongoClient('mongodb://localhost:27017/')
    db = mc.sshkeys
    col = db.hosts
    logger = logging.getLogger('sshkeyscan')

    def __init__(self, target_q, stop_evt, retry_count, timeout):
        super().__init__()
        self.target_q = target_q
        self.stop_evt = stop_evt
        self.retry_count = retry_count
        self.timeout = timeout

    def run(self): 
        while not self.stop_evt.is_set() and not self.target_q.empty(): 
            try:
          
                ''' 
                   socket and paramiko require a unicode IP, but we'll use both 
                   unicode and non-unicode for storage to ensure uniformity of
                   data.
                '''
      
                curr_ip = self.target_q.get()
                str_ip = str(curr_ip)
                fqdn = socket.getfqdn(str_ip)
                sshKey = self._get_key(str_ip, self.retry_count, self.timeout)

                if sshKey is not None:

                   '''
                     we got a response from the socket, and a key was provided

                     we'll then take the response and extract the clean key, key type,
                     and other data.  construct the db schema, and then hash it.  then
                     check db for existing record for this IP address, and then further
                     interrogate that record for a matching hash.  if found, skip, else 
                     upsert. 
                   '''

                    printableType = sshKey.get_name()
                    printableKey = base64.encodestring(sshKey.__str__()).decode('utf-8').replace('\n', '')
                    sshFingerprint = hashlib.md5(sshKey.__str__()).hexdigest()
                    printableFingerprint = ':'.join(a+b for a,b in zip(sshFingerprint[::2], sshFingerprint[1::2]))
          
                    doc = {
                      'timestamp': int(time.time()), 
                      'fqdn': fqdn, 
                      'key_type': printableType, 
                      'key': printableKey, 
                      'fingerprint': printableFingerprint
                    }

                    doc_hash = hashlib.md5(repr(sorted(doc)).encode('utf-8')).hexdigest()
                    curr_doc = self.col.find({"_id": str_ip})
                    if(curr_doc.count() > 0):
                          exists = False
                          for i in range(curr_doc.count()):
                              entry = curr_doc.__getitem__(i) 
                              for item in entry["data"]:
                                  if(item["md5hash"] == doc_hash):
                                      exists = True
                                      logger.info("duplicate key set for host %s (%s)" %(str_ip, doc_hash))
                                      self.target_q.task_done()


                          if not exists:
                              doc["md5hash"] = doc_hash
                              self.col.update_one({"_id": str_ip}, {"$push":{"data": doc}})
                              logger.info("updated existing key set for host %s: " % str_ip)
                              self.target_q.task_done()
                          
                    else:
                        doc["md5hash"] = doc_hash
                        doc_id = self.col.insert_one({"_id": str_ip, "data": [doc]}).inserted_id
                        logger.info("inserted key set with id %s" %(doc_id))
                        self.target_q.task_done()
  
                else:
                    self.target_q.task_done()
                    continue
    
            except Exception as e:
                logger.debug("caught exception")
                logger.debug(e)

        else:
            if self.target_q.empty():
                logger.debug("queue empty; finished...")
            else:
                logger.debug("finished via else, queue not empty...")


        #print(self.target_q.unfinished_tasks)


    def _get_key(self, target, retry_count, timeout):
 
        logger = logging.getLogger('sshkeyscan')

        while retry_count > 0:
       
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((target, int(sys.argv[2])))
                trans = paramiko.Transport(sock)
                trans.start_client()
                key = trans.get_remote_server_key()
                trans.close()
                retry_count = 0
                return key
    
            except socket.error as e:
                retry_count -= 1
                if retry_count == 0:
                  logger.debug("all retries failed - socket error to %s:%s: %s" %(target, sys.argv[2], e))
                continue
     
            except paramiko.SSHException as e:
                retry_count -= 1
                if retry_count == 0: 
                    logger.debug("all retries failed - ssh error to %s:%s: %s" %(target, sys.argv[2], e))
                continue
        
            except Exception as e:
                logger.debug("get_key failed for target %s:" %(target))
                logger.debug(e)

 
if __name__ == '__main__':

    try:
 
        if len(sys.argv) != 6:
            print("\n")
            print("%s" % sys.argv[0])
            print("\n")
            print("scans provided subnetwork for accessible sshd processes, and")
            print("records the host key found in local mongo db (sshkeys)")
            print("collection 'hosts'.")
            print("\n")
            print("Usage: %s <ip_net/mask> <port> <num_threads> <num_retries> <timeout>" % sys.argv[0])
            print("\n")
            quit()
      

        logger = logging.getLogger('sshkeyscan')
        logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s %(threadName)s [%(levelname)s]: %(message)s')
        fh = logging.handlers.RotatingFileHandler('sshkeyscan.log', maxBytes=209715200, backupCount=50)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)
        logger.addHandler(fh)
        sh = logging.StreamHandler(sys.stdout)
        sh.setLevel(logging.INFO)
        sh.setFormatter(formatter)
        logger.addHandler(sh)

        retry_count = int(sys.argv[4])
        timeout = int(sys.argv[5])
        q = queue.Queue(maxsize=0)
        stop_evt = threading.Event()
        ip_net = ipaddress.ip_network(str(sys.argv[1]))
        all_hosts = list(ip_net.hosts())

        logger.info("processing %i hosts... ctrl+c to stop" % len(all_hosts))

        for i in range(len(all_hosts)):
            q.put(all_hosts[i])
    
        threads = []
        num_threads = int(sys.argv[3])
        for i in range(num_threads):
            threads.append(KeyFinder(q, stop_evt, retry_count, timeout))
        handler = SigHandler(stop_evt, threads)
        signal.signal(signal.SIGINT, handler)
    
        for i, t in enumerate(threads):
            t.daemon = True
            t.start()
    
        q.join()
        logger.info("completed...")

    except Exception as e:
        import traceback
        traceback.print_exc()
