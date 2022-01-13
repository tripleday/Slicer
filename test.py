import secrets
import math
import hashlib
from helpfunctions import generate_large_prime, hash_to_prime, is_prime, concat, bezoute_coefficients, mul_inv, list_product, hash_to_length,\
    string_to_number, hashset, string_to_prime, generate_two_large_safe_primes, xgcd, aes_encode, aes_decode, xor_hexstr,\
    hmac128, hmac128_low, hmac256, hashsetAdd, get_size

from main import acc_setup, add, prove_membership, batch_add, test_trapdoor_setup
    
from unittest import TestCase
import unittest
import datetime
import numpy as np
import pandas as pd
import pickle
import sys
import json
import random
import hmac


def create_list(size):
    res = []
    for i in range(size):
        x = secrets.randbelow(pow(2, 256))
        res.append(x)
    return res



class SlicerTest(TestCase):
    def test_hash_to_prime(self):
        x = secrets.randbelow(pow(2, 256))
        #print(x)
        h, nonce = hash_to_prime(x, 128)
        #print(h)
        #print(nonce)
        self.assertTrue(is_prime(h))
        self.assertTrue(h, math.log2(h) < 128)


    def test_fast_accmulation(self):
        # n, A0, S = acc_setup()
        # print(is_prime((p-1)//2))
        # print(is_prime((q-1)//2))

        p = 252533614457563255817176556954479732787
        q = 144382690536755041477176940054403505719
        n = 36461482706354564422592875042006590908268153693683612285024099145347146308853
        A0 = 4
        f = open('wiki_1m_prime.pk','rb')  
        primes_list = pickle.load(f)


        for total in [100000]:
            print(total)
            primes_list = primes_list[:total]

            # successively exponentiation
            start_time = datetime.datetime.now() 
            A_final1 = A0
            for e in primes_list:        
                A_final1 = pow(A_final1, e, n) 
            end_time = datetime.datetime.now()     
            print((end_time - start_time).total_seconds()) 

            # successively exponentiation with phi
            start_time = datetime.datetime.now() 
            A_final2 = A0
            for e in primes_list:        
                A_final2 = pow(A_final2, e%((p-1)*(q-1)), n) 
            end_time = datetime.datetime.now()     
            print((end_time - start_time).total_seconds()) 

            # nomal product
            start_time = datetime.datetime.now() 
            product = 1
            for e in primes_list: 
                product *= e
            acc1 = pow(A0,product,n)
            end_time = datetime.datetime.now()     
            print((end_time - start_time).total_seconds()) 

            # normal prodcut with phi
            start_time = datetime.datetime.now() 
            product = 1
            for e in primes_list: 
                product *= e
            acc2 = pow(A0,product%((p-1)*(q-1)),n)
            end_time = datetime.datetime.now()     
            print((end_time - start_time).total_seconds()) 

            # fast product
            start_time = datetime.datetime.now() 
            product = list_product(primes_list)
            acc1 = pow(A0,product,n)
            end_time = datetime.datetime.now()     
            print((end_time - start_time).total_seconds()) 

            # fast prodcut with phi
            start_time = datetime.datetime.now() 
            product = list_product(primes_list)
            acc2 = pow(A0,product%((p-1)*(q-1)),n)
            end_time = datetime.datetime.now()     
            print((end_time - start_time).total_seconds()) 


            print(A_final1==A_final2)
            print(A_final2==acc1)
            print(acc1==acc2)


    def test_acc_setup(self):
        p, q, n, g = acc_setup()
        print(p) # 253699952048629878783745260665553993359
        print(q) # 284802804588708767570121178795305085943
        print(n) # 72254457867470719938938495559676057516509089362369981914474612970086346252537
        print(g) # 4


    def test_fast_sethash(self):
        q = 565150966737506074175715793592567238421

        l = []
        for i in range(10000):
            l.append(hashlib.sha256(str(i).encode()).hexdigest())
        
        # l = ['a', 'b']

        start_time = datetime.datetime.now() 
        product = 1
        for b in l:
            # print(string_to_number(b))
            product *= string_to_number(b) 
        h1 = product % q
        end_time = datetime.datetime.now()     
        print((end_time - start_time).total_seconds()) 

        start_time = datetime.datetime.now() 
        h2 = 1
        for b in l:
            # print(string_to_number(b))
            h2 = (h2*string_to_number(b)) % q
        end_time = datetime.datetime.now()     
        print((end_time - start_time).total_seconds()) 
        print(h1==h2)


    def test_sethash(self):
        # q = generate_large_prime(129)
        # q = 320082893822846608701648223729735861199 # 128 bit
        q = 565150966737506074175715793592567238421 # 129 bit
        # print(q)
        # print(math.log2(q))
        l = ['a', 'b']

        start_time = datetime.datetime.now() 
        h2 = 1
        for b in l:
            print(hashlib.sha256(b.encode()).hexdigest())
            print(string_to_number(b))
            h2 = (h2*string_to_number(b)) % q
        end_time = datetime.datetime.now()     
        print((end_time - start_time).total_seconds()) 
        # print(hashset(l,q))


    def test_string_prime(self):
        l = ['a', 'b']
        print(string_to_prime(l[0]))
        print(string_to_prime(l[1]))


    def test_trapdoor_setup(self):
        p, q, n, e, d = test_trapdoor_setup()

        print(p) # 283997039141845171343237386733114773607
        print(q) # 265093400314887187638254500874307471479
        print(n) # 75285740785471847697928274317260872220053075039512266400838219410235694454753
        print(e) # 65537
        print(d) # 24421312592250881337416378285711107962134904078804043489873387100470794191149
        print(e*d%((p-1)*(q-1)))
        
        tpP = 283997039141845171343237386733114773607
        tpQ = 265093400314887187638254500874307471479
        tpN = 75285740785471847697928274317260872220053075039512266400838219410235694454753
        tpE = 65537
        tpD = 24421312592250881337416378285711107962134904078804043489873387100470794191149

        print(tpE*tpD%((tpP-1)*(tpQ-1)))

        c = 2345
        m = pow(c,tpE,tpN)
        print(m)
        c = pow(m,tpD,tpN)
        print(c)


    def test_rv_pickle(self):   
        for bits in [8, 16, 24, 32]:
            for amount in [10000, 20000, 40000, 80000, 160000]:
                RvList={}
                for i in range(amount):    
                    x = secrets.randbelow(pow(2, bits))
                    if x in RvList:
                        RvList[x].append(i)
                    else:
                        RvList[x]=[i]

                print(len(RvList))
                with open('.\data\Rv_'+str(bits)+'bit_'+str(amount)+'.pk', 'wb') as f:
                    pickle.dump(RvList, f)

        for bits in [8, 16, 24, 32]:
            for amount in [2000, 4000, 8000, 16000, 32000]:
                RvList={}
                for i in range(amount):    
                    x = secrets.randbelow(pow(2, bits))
                    if x in RvList:
                        RvList[x].append(i+160000)
                    else:
                        RvList[x]=[i]

                print(len(RvList))
                with open('.\data\Rv_'+str(bits)+'bit_'+str(amount)+'_add.pk', 'wb') as f:
                    pickle.dump(RvList, f)


    def test_aes(self):     
        key = 'aes'  # 密钥长度必须为16、24或32位，分别对应AES-128、AES-192和AES-256
        text = '1' 
        print(aes_encode(key, text))
        print(aes_decode(key, 'a1b45b3b8f92ba774ca238dea6472da0'))


    def test_xor(self):
        a = 'fa4ee7d173f2d97ee79022d1a7355bcf'
        b = 'fa4ee7d173f2d97ee79022d1a7355bce'
        # print(str.encode(a).hex())
        # print(str.encode(b).hex())
        
        print(xor_hexstr(a, b))


    def test_hmac(self):
        key = 'secret'
        text = 'Hello, world!'
        print(hmac128_low(key, text))
        print(hmac128(key, text)) # 使用了优化的 C 或内联实现，对放入内存的消息能处理得更快
        print(hmac256(key, text))


    def test_alg_correctness(self):    
        tpP = 283997039141845171343237386733114773607
        tpQ = 265093400314887187638254500874307471479
        tpN = 75285740785471847697928274317260872220053075039512266400838219410235694454753
        tpE = 65537
        tpD = 24421312592250881337416378285711107962134904078804043489873387100470794191149
        sethashQ = 565150966737506074175715793592567238421 # 129 bits
        acP = 253699952048629878783745260665553993359
        acQ = 284802804588708767570121178795305085943
        acN = 72254457867470719938938495559676057516509089362369981914474612970086346252537
        acG = 4
        PRFkey = 'prf'
        AESkey = 'aes'

        for bits in [16]:  
            print('bits: '+str(bits))  
            amount = 10000
            # for amount in [10000, 20000, 40000, 80000, 160000]:    
            print('build amount:'+str(amount))
            f = open('.\data\Rv_'+str(bits)+'bit_'+str(amount)+'.pk','rb')  
            RvList = pickle.load(f)
            # print(len(RvList))

            cts = {}
            for v in RvList.keys():
                b = "{0:b}".format(v).zfill(bits)
                for i in range(bits):
                    ct = b[:i] + ('0' if b[i]=='1' else '1') + ('>' if b[i]=='0' else '<')                
                    if ct in cts:
                        cts[ct].extend(RvList[v])
                    else:
                        cts[ct]=RvList[v].copy()
            I = {}
            tss = {}
            S = {}
            for w in RvList:
                t0 = secrets.randbelow(pow(2, 128))
                tss[w]=[t0,0]
                G1 = hmac128(PRFkey,str(w)+'1')
                G2 = hmac128(PRFkey,str(w)+'2')
                c = 0
                hList = []
                for R in RvList[w]:
                    l = hmac128(G1, str(t0)+'-'+str(c))
                    encryptedR = aes_encode(AESkey, str(R))
                    d = xor_hexstr(hmac128(G2, str(t0)+'-'+str(c)), encryptedR)
                    I[l] = d
                    c = c+1
                    hList.append(encryptedR)
                RSethash = hashset(hList, sethashQ)
                S[str(t0)+'-0-'+G1+'-'+G2] = RSethash
            for w in cts:
                t0 = secrets.randbelow(pow(2, 128))
                tss[w]=[t0,0]
                G1 = hmac128(PRFkey,w+'1')
                G2 = hmac128(PRFkey,w+'2')
                c = 0
                hList = []
                for R in cts[w]:
                    l = hmac128(G1, str(t0)+'-'+str(c))
                    encryptedR = aes_encode(AESkey, str(R))
                    d = xor_hexstr(hmac128(G2, str(t0)+'-'+str(c)), encryptedR)
                    I[l] = d
                    c = c+1
                    hList.append(encryptedR)
                RSethash = hashset(hList, sethashQ)
                S[str(t0)+'-0-'+G1+'-'+G2] = RSethash
            X = []
            for g in S:
                x = string_to_prime(g+'-'+str(S[g]))
                X.append(x)
            product = list_product(X)
            Ac = pow(acG,product%((acP-1)*(acQ-1)),acN)
                
            ############################# insert based on 160,000 original data
            amount = 2000
            # for amount in [2000, 4000, 8000, 16000, 32000]:
            print('add amount:'+str(amount))
            f = open('.\data\Rv_'+str(bits)+'bit_'+str(amount)+'_add.pk','rb')  
            RvListAdd = pickle.load(f)

            ctsAdd = {}
            for v in RvListAdd.keys():
                b = "{0:b}".format(v).zfill(bits)
                for i in range(bits):
                    ct = b[:i] + ('0' if b[i]=='1' else '1') + ('>' if b[i]=='0' else '<')                
                    if ct in ctsAdd:
                        ctsAdd[ct].extend(RvListAdd[v])
                    else:
                        ctsAdd[ct]=RvListAdd[v].copy()
            X_add=[]
            for w in RvListAdd:
                G1 = hmac128(PRFkey,str(w)+'1')
                G2 = hmac128(PRFkey,str(w)+'2')
                if w in tss:
                    t = tss[w][0]
                    j = tss[w][1]
                    h = S.pop(str(t)+'-'+str(j)+'-'+G1+'-'+G2)
                    t = pow(t, tpD, tpN)
                    j = j+1
                else:
                    t = secrets.randbelow(pow(2, 128))
                    j = 0  
                    h = 1
                tss[w]=[t,j]
                c = 0
                hList = []
                for R in RvListAdd[w]:
                    l = hmac128(G1, str(t)+'-'+str(c))
                    encryptedR = aes_encode(AESkey, str(R))
                    d = xor_hexstr(hmac128(G2, str(t)+'-'+str(c)), encryptedR)
                    I[l] = d
                    c = c+1
                    hList.append(encryptedR)
                RSethash = hashsetAdd(h, hList, sethashQ)
                S[str(t)+'-'+str(j)+'-'+G1+'-'+G2] = RSethash
                x = string_to_prime(str(t)+'-'+str(j)+'-'+G1+'-'+G2+'-'+str(RSethash))
                X.append(x)
                X_add.append(x)
            for w in ctsAdd:
                G1 = hmac128(PRFkey,w+'1')
                G2 = hmac128(PRFkey,w+'2')
                if w in tss:
                    t = tss[w][0]
                    j = tss[w][1]
                    h = S.pop(str(t)+'-'+str(j)+'-'+G1+'-'+G2)
                    t = pow(t, tpD, tpN)
                    j = j+1
                else:
                    t = secrets.randbelow(pow(2, 128))
                    j = 0  
                    h = 1
                tss[w]=[t,j]
                c = 0
                hList = []
                for R in ctsAdd[w]:
                    l = hmac128(G1, str(t)+'-'+str(c))
                    encryptedR = aes_encode(AESkey, str(R))
                    d = xor_hexstr(hmac128(G2, str(t)+'-'+str(c)), encryptedR)
                    I[l] = d
                    c = c+1
                    hList.append(encryptedR)
                RSethash = hashsetAdd(h, hList, sethashQ)
                S[str(t)+'-'+str(j)+'-'+G1+'-'+G2] = RSethash
                x = string_to_prime(str(t)+'-'+str(j)+'-'+G1+'-'+G2+'-'+str(RSethash))
                X.append(x)
                X_add.append(x)
            p = list_product(X_add)
            product *= p
            Ac = pow(Ac,p%((acP-1)*(acQ-1)),acN)

            ########################################### search
            # =
            randomAmount = 10
            queryValues = []
            for _ in range(randomAmount):
                queryValues.append(secrets.randbelow(pow(2, bits)))
            qts4search = []
            for ith in range(randomAmount):
                queryValue = queryValues[ith]     
                qt = []
                if queryValue in tss:
                    t = tss[queryValue][0]
                    j = tss[queryValue][1]
                    G1 = hmac128(PRFkey,str(queryValue)+'1')
                    G2 = hmac128(PRFkey,str(queryValue)+'2')
                    qt.append([t,j,G1,G2])
                qts4search.append(qt)
            rs4search = []
            for ith_qts in qts4search:
                er = []
                if ith_qts:
                    tj = ith_qts[0][0]
                    j= ith_qts[0][1]
                    G1 = ith_qts[0][2]
                    G2 = ith_qts[0][3]
                    i = j
                    t = tj
                    while i >= 0:
                        c = 0
                        l = hmac128(G1, str(t)+'-'+str(c))
                        while l in I:
                            r = xor_hexstr(hmac128(G2, str(t)+'-'+str(c)), I[l])
                            er.append(r)
                            c = c+1
                            l = hmac128(G1, str(t)+'-'+str(c))
                        t = pow(t, tpE, tpN)
                        i = i-1
                rs4search.append(er)  
            for ind in range(randomAmount):
                if not qts4search[ind]:
                    continue
                tj = qts4search[ind][0][0]
                j= qts4search[ind][0][1]
                G1 = qts4search[ind][0][2]
                G2 = qts4search[ind][0][3]
                er = rs4search[ind]
                h = hashset(er, sethashQ)
                x = string_to_prime(str(tj)+'-'+str(j)+'-'+G1+'-'+G2+'-'+str(h))
                vo = pow(acG, product//x, acN)
                if not (Ac==pow(vo,x,acN)):
                    print('error')
                # print(str(tj)+'-'+str(j)+'-'+G1+'-'+G2)
                # print(er)
                # print(h)
                # print(x)
                # print(Ac)
                # print(vo)

            # < >
            queryValues = []
            for _ in range(randomAmount):
                v = secrets.randbelow(pow(2, bits))
                mc = '<' if random.randint(0,1)==0 else '>'
                queryValues.append([v,mc])
            qts4search = []
            for ith in range(randomAmount):
                v = queryValues[ith][0]
                mc = queryValues[ith][1]
                b = "{0:b}".format(v).zfill(bits)
                tuples = []
                for i in range(bits):
                    tup = b[:i] + b[i] + mc  
                    tuples.append(tup)
                random.shuffle(tuples)
                qts = []
                for tuple in tuples:
                    if tuple in tss:
                        t = tss[tuple][0]
                        j = tss[tuple][1]
                        G1 = hmac128(PRFkey,tuple+'1')
                        G2 = hmac128(PRFkey,tuple+'2')
                        qts.append([t,j,G1,G2])
                qts4search.append(qts)
            rs4search = []
            for ith_qts in qts4search:
                rs = []
                if ith_qts:
                    for qt in ith_qts:
                        er = []
                        tj = qt[0]
                        j= qt[1]
                        G1 = qt[2]
                        G2 = qt[3]
                        i = j
                        t = tj
                        while i >= 0:
                            c = 0
                            l = hmac128(G1, str(t)+'-'+str(c))
                            while l in I:
                                r = xor_hexstr(hmac128(G2, str(t)+'-'+str(c)), I[l])
                                er.append(r)
                                c = c+1
                                l = hmac128(G1, str(t)+'-'+str(c))
                            t = pow(t, tpE, tpN)
                            i = i-1
                        rs.append(er)
                rs4search.append(rs)
            for ind in range(randomAmount):
                if not qts4search[ind]:
                    continue
                for ith in range(len(qts4search[ind])):
                    tj = qts4search[ind][ith][0]
                    j= qts4search[ind][ith][1]
                    G1 = qts4search[ind][ith][2]
                    G2 = qts4search[ind][ith][3]
                    er = rs4search[ind][ith]
                    h = hashset(er, sethashQ)
                    x = string_to_prime(str(tj)+'-'+str(j)+'-'+G1+'-'+G2+'-'+str(h))
                    vo = pow(acG, product//x, acN)
                    if not (Ac==pow(vo,x,acN)):
                        print('error')
                    # print(str(tj)+'-'+str(j)+'-'+G1+'-'+G2)
                    # print(er)
                    # print(h)
                    # print(x)
                    # print(Ac)
                    # print(vo)


    def test_alg_getsize(self):    
        tpP = 283997039141845171343237386733114773607
        tpQ = 265093400314887187638254500874307471479
        tpN = 75285740785471847697928274317260872220053075039512266400838219410235694454753
        tpE = 65537
        tpD = 24421312592250881337416378285711107962134904078804043489873387100470794191149
        sethashQ = 565150966737506074175715793592567238421 # 129 bits
        acP = 253699952048629878783745260665553993359
        acQ = 284802804588708767570121178795305085943
        acN = 72254457867470719938938495559676057516509089362369981914474612970086346252537
        acG = 4
        PRFkey = 'prf'
        AESkey = 'aes'

        for bits in [8, 16, 24]:  
            print('bits: '+str(bits))  
            amount = 160000
            # for amount in [10000, 20000, 40000, 80000, 160000]:    
            print('build amount:'+str(amount))
            f = open('.\data\Rv_'+str(bits)+'bit_'+str(amount)+'.pk','rb')  
            RvList = pickle.load(f)
            # print(len(RvList))

            start_time = datetime.datetime.now() 
            cts = {}
            for v in RvList.keys():
                b = "{0:b}".format(v).zfill(bits)
                for i in range(bits):
                    ct = b[:i] + ('0' if b[i]=='1' else '1') + ('>' if b[i]=='0' else '<')                
                    if ct in cts:
                        cts[ct].extend(RvList[v])
                    else:
                        cts[ct]=RvList[v].copy()
            I = {}
            tss = {}
            S = {}
            for w in RvList:
                t0 = secrets.randbelow(pow(2, 128))
                tss[w]=[t0,0]
                G1 = hmac128(PRFkey,str(w)+'1')
                G2 = hmac128(PRFkey,str(w)+'2')
                c = 0
                hList = []
                for R in RvList[w]:
                    l = hmac128(G1, str(t0)+'-'+str(c))
                    encryptedR = aes_encode(AESkey, str(R))
                    d = xor_hexstr(hmac128(G2, str(t0)+'-'+str(c)), encryptedR)
                    I[l] = d
                    c = c+1
                    hList.append(encryptedR)
                RSethash = hashset(hList, sethashQ)
                S[str(t0)+'-0-'+G1+'-'+G2] = RSethash
            for w in cts:
                t0 = secrets.randbelow(pow(2, 128))
                tss[w]=[t0,0]
                G1 = hmac128(PRFkey,w+'1')
                G2 = hmac128(PRFkey,w+'2')
                c = 0
                hList = []
                for R in cts[w]:
                    l = hmac128(G1, str(t0)+'-'+str(c))
                    encryptedR = aes_encode(AESkey, str(R))
                    d = xor_hexstr(hmac128(G2, str(t0)+'-'+str(c)), encryptedR)
                    I[l] = d
                    c = c+1
                    hList.append(encryptedR)
                RSethash = hashset(hList, sethashQ)
                S[str(t0)+'-0-'+G1+'-'+G2] = RSethash
            end_time = datetime.datetime.now()     
            print('index time: '+str((end_time - start_time).total_seconds())) 
            start_time = datetime.datetime.now() 
            X = []
            for g in S:
                x = string_to_prime(g+'-'+str(S[g]))
                X.append(x)
            product = list_product(X)
            Ac = pow(acG,product%((acP-1)*(acQ-1)),acN)
            end_time = datetime.datetime.now()     
            print('ADS time: '+str((end_time - start_time).total_seconds())) 
            print('I size: '+str(get_size(I)))
            print('T size: '+str(get_size(tss)))
            print('S size: '+str(get_size(S)))
            print('X size: '+str(get_size(X))+'\n')

                # if bits==24:
                #     continue
                # ########################################### search
                # # =
                # randomAmount4equal = 500
                # queryValues = []
                # for _ in range(randomAmount4equal):
                #     queryValues.append(secrets.randbelow(pow(2, bits)))
                # qts4search = []
                # for ith in range(randomAmount4equal):
                #     queryValue = queryValues[ith]     
                #     qt = []
                #     if queryValue in tss:
                #         t = tss[queryValue][0]
                #         j = tss[queryValue][1]
                #         G1 = hmac128(PRFkey,str(queryValue)+'1')
                #         G2 = hmac128(PRFkey,str(queryValue)+'2')
                #         qt.append([t,j,G1,G2])
                #     qts4search.append(qt)
                # rs4search = []
                # start_time = datetime.datetime.now() 
                # for ith_qts in qts4search:
                #     er = []
                #     if ith_qts:
                #         tj = ith_qts[0][0]
                #         j= ith_qts[0][1]
                #         G1 = ith_qts[0][2]
                #         G2 = ith_qts[0][3]
                #         i = j
                #         t = tj
                #         while i >= 0:
                #             c = 0
                #             l = hmac128(G1, str(t)+'-'+str(c))
                #             while l in I:
                #                 r = xor_hexstr(hmac128(G2, str(t)+'-'+str(c)), I[l])
                #                 er.append(r)
                #                 c = c+1
                #                 l = hmac128(G1, str(t)+'-'+str(c))
                #             t = pow(t, tpE, tpN)
                #             i = i-1
                #     rs4search.append(er)  
                # end_time = datetime.datetime.now()     
                # print('search time for =: '+str((end_time - start_time).total_seconds())) 
                # vo4search = []
                # start_time = datetime.datetime.now() 
                # for ind in range(randomAmount4equal):
                #     if not qts4search[ind]:
                #         continue
                #     tj = qts4search[ind][0][0]
                #     j= qts4search[ind][0][1]
                #     G1 = qts4search[ind][0][2]
                #     G2 = qts4search[ind][0][3]
                #     er = rs4search[ind]
                #     h = hashset(er, sethashQ)
                #     x = string_to_prime(str(tj)+'-'+str(j)+'-'+G1+'-'+G2+'-'+str(h))
                #     vo = pow(acG, product//x, acN)
                #     # if not (Ac==pow(vo,x,acN)):
                #     #     print('error')
                #     vo4search.append(vo)
                # end_time = datetime.datetime.now()     
                # print('vo generation time for =: '+str((end_time - start_time).total_seconds())) 
                # qtsSize=0
                # for e in qts4search:
                #     qtsSize+=get_size(e)
                # print('= token size: '+str(qtsSize/randomAmount4equal))
                # rsSize=0
                # for e in rs4search:
                #     rsSize+=get_size(e)
                # print('= result size: '+str(rsSize/randomAmount4equal))
                # voSize=0
                # for e in vo4search:
                #     voSize+=get_size(e)
                # print('= vo size: '+str(voSize/randomAmount4equal)+'\n')

                # # < >
                # randomAmount4order = 10
                # queryValues = []
                # for _ in range(randomAmount4order):
                #     v = secrets.randbelow(pow(2, bits))
                #     mc = '<' if random.randint(0,1)==0 else '>'
                #     queryValues.append([v,mc])
                # qts4search = []
                # for ith in range(randomAmount4order):
                #     v = queryValues[ith][0]
                #     mc = queryValues[ith][1]
                #     b = "{0:b}".format(v).zfill(bits)
                #     tuples = []
                #     for i in range(bits):
                #         tup = b[:i] + b[i] + mc  
                #         tuples.append(tup)
                #     random.shuffle(tuples)
                #     qts = []
                #     for tuple in tuples:
                #         if tuple in tss:
                #             t = tss[tuple][0]
                #             j = tss[tuple][1]
                #             G1 = hmac128(PRFkey,tuple+'1')
                #             G2 = hmac128(PRFkey,tuple+'2')
                #             qts.append([t,j,G1,G2])
                #     qts4search.append(qts)
                # rs4search = []
                # start_time = datetime.datetime.now() 
                # for ith_qts in qts4search:
                #     rs = []
                #     if ith_qts:
                #         for qt in ith_qts:
                #             er = []
                #             tj = qt[0]
                #             j= qt[1]
                #             G1 = qt[2]
                #             G2 = qt[3]
                #             i = j
                #             t = tj
                #             while i >= 0:
                #                 c = 0
                #                 l = hmac128(G1, str(t)+'-'+str(c))
                #                 while l in I:
                #                     r = xor_hexstr(hmac128(G2, str(t)+'-'+str(c)), I[l])
                #                     er.append(r)
                #                     c = c+1
                #                     l = hmac128(G1, str(t)+'-'+str(c))
                #                 t = pow(t, tpE, tpN)
                #                 i = i-1
                #             rs.append(er)
                #     rs4search.append(rs)
                # end_time = datetime.datetime.now()     
                # print('search time for < >: '+str((end_time - start_time).total_seconds())) 
                # vo4search = []
                # start_time = datetime.datetime.now() 
                # for ind in range(randomAmount4order):
                #     if not qts4search[ind]:
                #         continue
                #     vos = []
                #     for ith in range(len(qts4search[ind])):
                #         tj = qts4search[ind][ith][0]
                #         j= qts4search[ind][ith][1]
                #         G1 = qts4search[ind][ith][2]
                #         G2 = qts4search[ind][ith][3]
                #         er = rs4search[ind][ith]
                #         h = hashset(er, sethashQ)
                #         x = string_to_prime(str(tj)+'-'+str(j)+'-'+G1+'-'+G2+'-'+str(h))
                #         vo = pow(acG, product//x, acN)
                #         # if not (Ac==pow(vo,x,acN)):
                #         #     print('error')
                #         vos.append(vo)
                #     vo4search.append(vos)
                # end_time = datetime.datetime.now()    
                # print('vo generation time for < >: '+str((end_time - start_time).total_seconds()))  
                # qtsSize=0
                # for e in qts4search:
                #     qtsSize+=get_size(e)
                # print('< > token size: '+str(qtsSize/randomAmount4order))
                # rsSize=0
                # for e in rs4search:
                #     rsSize+=get_size(e)
                # print('< > result size: '+str(rsSize/randomAmount4order))
                # voSize=0
                # for e in vo4search:
                #     voSize+=get_size(e)
                # print('< > vo size: '+str(voSize/randomAmount4order)+'\n')


            ############################# insert based on 160,000 original data
            S_original = {}
            S_original.update(S)
            tss_original = {}
            tss_original.update(tss)
            I_original = {}
            I_original.update(I)
            X_original = X.copy()
            # insertAmount = 32000
            for insertAmount in [2000, 4000, 8000, 16000, 32000]:
                print('add amount:'+str(insertAmount))
                f = open('.\data\Rv_'+str(bits)+'bit_'+str(insertAmount)+'_add.pk','rb')  
                RvListAdd = pickle.load(f)               
                S = {}
                S.update(S_original)
                tss = {}
                tss.update(tss_original)
                I = {}
                I.update(I_original)
                X = X_original.copy()

                start_time = datetime.datetime.now() 
                ctsAdd = {}
                for v in RvListAdd.keys():
                    b = "{0:b}".format(v).zfill(bits)
                    for i in range(bits):
                        ct = b[:i] + ('0' if b[i]=='1' else '1') + ('>' if b[i]=='0' else '<')                
                        if ct in ctsAdd:
                            ctsAdd[ct].extend(RvListAdd[v])
                        else:
                            ctsAdd[ct]=RvListAdd[v].copy()
                X_add=[]
                S_add={}
                for w in RvListAdd:
                    G1 = hmac128(PRFkey,str(w)+'1')
                    G2 = hmac128(PRFkey,str(w)+'2')
                    if w in tss:
                        t = tss[w][0]
                        j = tss[w][1]
                        h = S.pop(str(t)+'-'+str(j)+'-'+G1+'-'+G2)
                        t = pow(t, tpD, tpN)
                        j = j+1
                    else:
                        t = secrets.randbelow(pow(2, 128))
                        j = 0  
                        h = 1
                    tss[w]=[t,j]
                    c = 0
                    hList = []
                    for R in RvListAdd[w]:
                        l = hmac128(G1, str(t)+'-'+str(c))
                        encryptedR = aes_encode(AESkey, str(R))
                        d = xor_hexstr(hmac128(G2, str(t)+'-'+str(c)), encryptedR)
                        I[l] = d
                        c = c+1
                        hList.append(encryptedR)
                    RSethash = hashsetAdd(h, hList, sethashQ)
                    S[str(t)+'-'+str(j)+'-'+G1+'-'+G2] = RSethash
                    S_add[str(t)+'-'+str(j)+'-'+G1+'-'+G2] = RSethash
                for w in ctsAdd:
                    G1 = hmac128(PRFkey,w+'1')
                    G2 = hmac128(PRFkey,w+'2')
                    if w in tss:
                        t = tss[w][0]
                        j = tss[w][1]
                        h = S.pop(str(t)+'-'+str(j)+'-'+G1+'-'+G2)
                        t = pow(t, tpD, tpN)
                        j = j+1
                    else:
                        t = secrets.randbelow(pow(2, 128))
                        j = 0  
                        h = 1
                    tss[w]=[t,j]
                    c = 0
                    hList = []
                    for R in ctsAdd[w]:
                        l = hmac128(G1, str(t)+'-'+str(c))
                        encryptedR = aes_encode(AESkey, str(R))
                        d = xor_hexstr(hmac128(G2, str(t)+'-'+str(c)), encryptedR)
                        I[l] = d
                        c = c+1
                        hList.append(encryptedR)
                    RSethash = hashsetAdd(h, hList, sethashQ)
                    S[str(t)+'-'+str(j)+'-'+G1+'-'+G2] = RSethash
                    S_add[str(t)+'-'+str(j)+'-'+G1+'-'+G2] = RSethash
                end_time = datetime.datetime.now()     
                print('add index time: '+str((end_time - start_time).total_seconds())) 
                start_time = datetime.datetime.now() 
                for g in S_add:
                    x = string_to_prime(g+'-'+str(S[g]))
                    X.append(x)
                    X_add.append(x)
                p = list_product(X_add)
                product *= p
                Ac = pow(Ac,p%((acP-1)*(acQ-1)),acN)
                end_time = datetime.datetime.now()     
                print('add ADS time: '+str((end_time - start_time).total_seconds())+'\n') 



s = unittest.TestSuite()
testname = 'test_alg_getsize'
print(testname)
s.addTest(SlicerTest(testname))
#s.addTests([Test_Myclass1("test_sub"),Test_Myclass1("test_sum")])
fs = open(testname+'.txt',"w")
run = unittest.TextTestRunner(fs)
run.run(s)