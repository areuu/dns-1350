
import pykd

def get_address(localAddr):
    res = pykd.dbgCommand("x " + localAddr)
    result_count = res.count("\n") 
    if result_count == 0:
        print(localAddr + " not found.")
        return None 
    if result_count > 1:
        print("[=] Warning, more than one result for", localAddr)
    return res.split()[0].replace('`','')
    
    
SIG_CHUNK = [] 
_STANDARDALLOCLIST = int(get_address("dns!StandardAllocLists"), 16)
STANDARDALLOCLIST = [_STANDARDALLOCLIST, _STANDARDALLOCLIST+0x58 ,_STANDARDALLOCLIST+0x58*2,_STANDARDALLOCLIST+0x58*3]
STANDARDALLOCLIST_POOL = {0x50:[], 0x68:[], 0x88:[], 0xa0:[]}

class handle_allocate_chunk(pykd.eventHandler):
    def __init__(self):
        addr = get_address("dns!Mem_Alloc")
        if addr == None:
            return 

        print(addr)
        self.bp_init = pykd.setBp(int(addr, 16), self.enter_call_back)
        self.bp_nt_alloc_chunk = pykd.setBp(int(addr, 16) + 0x2b3, self.alloc_chunk)
        self.bp_alloc_chunk = pykd.setBp(int(addr, 16) + 0xbe, self.nt_alloc_chunk)   
        self.bp_end = None

    def enter_call_back(self):
        #print("[+] allocate req size: 0x%x"% pykd.reg("rbx"))
        pass 
        
    def return_call_back(self):

        return False
        
    def nt_alloc_chunk(self):
        #print("[+] NT chunk at 0x%x, 0x%x" %(pykd.reg("rcx"), pykd.reg("edi")))
        #return False 
        pass

    def alloc_chunk(self):
        print("[+] chunk alloc 0x%x, size: 0x%x" % (pykd.reg("rbp"), pykd.reg("r8d")))
        return False
        

class handle_free_chunk(pykd.eventHandler):
    def __init__(self):
        addr = get_address("dns!Mem_free")
        if addr == None:
            return 
        
        print(addr) 
        self.bp_init = pykd.setBp(int(addr, 16), self.enter_call_back)
        self.bp_nt_heap_free = pykd.setBp(int(addr, 16) + 0x168, self.nt_heap_free)
        self.bp_heap_free = pykd.setBp(int(addr, 16) + 0x21c, self.heap_free)
        
        self.chunk_mem = 0
        self.alloc_size = 0
        
    def nt_heap_free(self):
        #print("[+] NT heap free @ 0x%x" % (pykd.reg("rsi")))
        #return False 
        pass 
        
    def heap_free(self):
        self.chunk_mem = pykd.reg("rsi") 
        self.alloc_size = pykd.reg("ebp")
        
        print("[+] chunk free @ 0x%x, size: 0x%x" % (pykd.reg("rsi"), pykd.reg("ebp")))
        
        for mem in SIG_CHUNK:
            if (mem == self.chunk_mem):
                print(pykd.dbgCommand("db " + hex(pykd.reg("rsi")) + " l" + hex(pykd.reg("ebp"))))
                SIG_CHUNK.remove(mem)
        self.parse_pool()
        
    def enter_call_back(self):
        #print("[+] free"); 
        pass
        
    def parse_pool(self):
        print("[+] from standardalloclist")
        pool = 0 
        if self.alloc_size == 0x50:
            pool = STANDARDALLOCLIST[0]
        elif self.alloc_size == 0x68:
            pool = STANDARDALLOCLIST[1] 
        elif self.alloc_size == 0x88:
            pool = STANDARDALLOCLIST[2]
        elif self.alloc_size == 0xa0:
            pool = STANDARDALLOCLIST[3] 
           
        _free_pool = []
        free_ptr = pykd.loadQWords(pool,1)[0] 
        print("[+] 0x%x" % ( free_ptr), end='')
        col = 0
        for i in range(0x55):
            
            if free_ptr == 0x0:
                break;
            _free_pool.append(free_ptr)
            if pykd.loadBytes(free_ptr+4, 1)[0] == 0xee:    # free 
                next_ptr = pykd.loadQWords(free_ptr +8, 1)[0]
                free_ptr = next_ptr
                print(" -> 0x%x " % (next_ptr), end='')
            elif pykd.loadBytes(free_ptr+4,1)[0] == 0xbb:
                print(" 0x%x in use" % free_ptr)
            col=+1
            if col >= 8:
                print("")
                col = 0
            
        print("")    

class handle_sig(pykd.eventHandler):
    def __init__(self):
        addr = get_address("dns!SigWireRead")
        if addr == None:
            return
            
        alloc_addr = get_address("dns!Mem_Alloc")
        if alloc_addr == None:
            return 

        print(addr)
        print(alloc_addr)
        self.bp_init = pykd.setBp(int(addr, 16), self.enter_call_back)
        self.bp_signame_len = pykd.setBp(int(addr,16) + 0x5f, self.signame_len_call_back)
        self.bp_end = pykd.setBp(int(addr, 16) + 0xc7, self.sig_end)
        self._sig_copycountname = pykd.setBp(int(addr, 16) + 0xa3, self.sig_copycountname)
        self._sig_memcpy = pykd.setBp(int(addr, 16) + 0xb9, self.sig_memcpy)

        self.bp_nt_alloc_chunk = pykd.setBp(int(alloc_addr, 16) + 0x2b3, self.alloc_chunk)
        
        self.alloc_size = 0; 
        self.alloc_mem = 0; 
        self.alloc_index = 0; 
        
    def alloc_chunk(self):
        print("[+] chunk alloc 0x%x, size: 0x%x" % (pykd.reg("rbp"), pykd.reg("r8d")))
        self.alloc_mem = pykd.reg("rbp")
        self.alloc_size = pykd.reg("r8d")
        
        SIG_CHUNK.append(self.alloc_mem)
        
        return False

    def enter_call_back(self):
        print("");
        print("[+] ============ Sig")
        

    def signame_len_call_back(self):
        tmp_size_overflow =  pykd.reg("cx") + pykd.reg("di") + 0x14
        tmp_size = tmp_size_overflow & 0xffff
        print("[+] cx: 0x%x, di: 0x%x, len: 0x%x(0x%x) , ADD 0x38: 0x%x, real size(header): 0x%x" % ( pykd.reg("cx"), pykd.reg("di"),tmp_size,tmp_size_overflow, tmp_size +0x38, tmp_size + 0x38 +0x10))
        
    
    def sig_end(self):
        print("[+] =========== sig end")
        self.parse_pool()
        self.alloc_size = 0
        self.alloc_mem = 0
        print("")
        
    def sig_copycountname(self):            
        
        if self.alloc_mem != pykd.reg("rsi")-0x10:
            print("[!!!!!] something wrong")
    
        print("[+] ptr: 0x%x" % (pykd.reg("rsi")-0x10))
        print(pykd.dbgCommand("db " + hex(pykd.reg("rsi")-0x10 )+ " l" + hex(self.alloc_size)))
        
        print("[+] Next Chunk")
        print(pykd.dbgCommand("db " + hex(pykd.reg("rsi")-0x10+self.alloc_size) + " l" + hex(self.alloc_size)))
        
        
        #print(pykd.dbgCommand("db " + hex(pykd.reg("rsi")-0x10) + " la0"))


    def sig_memcpy(self):
        print("[+] memcpy")
        if self.alloc_mem != pykd.reg("rsi")-0x10:
            print("[!!!!!] something wrong")
            
        print(pykd.dbgCommand("db " + hex(pykd.reg("rsi")-0x10 )+ " l" + hex(self.alloc_size)))
        print("[+] Next Chunk")
        print(pykd.dbgCommand("db " + hex(pykd.reg("rsi")-0x10+self.alloc_size) + " l" + hex(self.alloc_size)))
        

    def parse_pool(self):
        print("[+] from standardalloclist")
        pool = 0 
        if self.alloc_size == 0x50:
            pool = STANDARDALLOCLIST[0]
        elif self.alloc_size == 0x68:
            pool = STANDARDALLOCLIST[1] 
        elif self.alloc_size == 0x88:
            pool = STANDARDALLOCLIST[2]
        elif self.alloc_size == 0xa0:
            pool = STANDARDALLOCLIST[3] 
           
        _free_pool = []
        free_ptr = pykd.loadQWords(pool,1)[0] 
        print("[+] 0x%x" % ( free_ptr), end='')
        col = 0
        for i in range(0x55):
            
            if free_ptr == 0x0:
                break;
            _free_pool.append(free_ptr)
            if pykd.loadBytes(free_ptr+4, 1)[0] == 0xee:    # free 
                next_ptr = pykd.loadQWords(free_ptr +8, 1)[0]
                free_ptr = next_ptr
                print(" -> 0x%x " % (next_ptr), end='')
            elif pykd.loadBytes(free_ptr+4,1)[0] == 0xbb:
                print(" 0x%x in use" % free_ptr)
            col=+1
            if col >= 8:
                print("")
                col = 0
            
        for i in _free_pool:
            if i == self.alloc_mem:
                print("[!!!!!] 0x%x" % self.alloc_mem)
        print("")
        
        
          
        
        
        

handle_allocate_chunk()
handle_free_chunk()
handle_sig()
pykd.go()





