'''
| Attred for Resource Discovery 
| Notes:          IoT node 
| type:           decentralized CP-ABE
| setting:        Pairing
| modified by:    Mohammed
| on:             08/05/2021 (not yet a final source code)
'''
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc, Input, Output
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
from charm.toolbox.symcrypto import AuthenticatedCryptoAbstraction, SymmetricCryptoAbstraction
from charm.core.math.pairing import hashPair as extractor
import time
from datetime import timedelta
#import secrets
from charm.toolbox.integergroup import IntegerGroup


# type annotations
pk_t = { 'g':G1, 'g2':G2, 'h':G1, 'f':G1, 'e_gg_alpha':GT }
mk_t = {'beta':ZR, 'g2_alpha':G2 }
sk_t = { 'D':G2, 'Dj':G2, 'Djp':G1, 'S':str }
ct_t = { 'C_tilde':GT, 'C':G1, 'Cy':G1, 'Cyp':G2 }

debug = False
class attredv1(ABEncMultiAuth):
         
    def __init__(self, groupObj):
        ABEnc.__init__(self)
        global util, group, group1
        util = SecretUtil(groupObj, verbose=False)	#Create Secret Sharing Scheme
        group = groupObj				#:Prime order group
        group1 = IntegerGroup()
        group1.paramgen(1024)

    def setup(self):
        g = group.random(G1)
        H = lambda x: group.hash(x, G1)
        GP = {'g':g, 'H': H}
        return GP

    def authsetup(self, GP, attributes):
        SK = {} #dictionary of {s: {alpha_i, beta_i}} 
        PK = {} #dictionary of {s: {e(g,g)^alpha_i, g^y}}
        for i in attributes: # This is done for each attribue that this AA handles
            alpha_i, beta_i = group.random(), group.random()   	# two random group elements
            e_gg_alpha_i = pair(GP['g'],GP['g']) ** alpha_i 	# first part of the PK
            g_beta_i = GP['g'] ** beta_i                          	# second part of the PK
            SK[i.upper()] = {'alpha_i': alpha_i, 'beta_i': beta_i} 	# The random group elements are the SK
            PK[i.upper()] = {'e(gg)^alpha_i': e_gg_alpha_i, 'g^beta_i': g_beta_i}
        print("Authority Setup for %s" % attributes)
        return (SK, PK)
    
 
    def encrypt(self, GP, pk, M, policy_str):
        '''Encrypt'''
        # M is a group element (will be used later as the key for symmetric encryption)
        # pk is a dictionary with all the attributes of all authorities put together.
        
        ###############################
        start_time = time.monotonic() # TIME STARTS HERE
        ###############################

        eta = 2 # Number of computational nodes
        s = group.random()  # choose a random integer number s
        
       # Additive secret sharing for the secret (s) ---------------
        s_i = []
        summ = 0
        for j in range(eta-1):
            s_i.append(int( group.random() / eta) )
            summ = summ + s_i[j]
        s_i.append(s - summ)
        # ---------------------------------------------------------

        w = group.init(ZR, 0) # set w to zero
        policy = util.createPolicy(policy_str)
        s_shares = util.calculateSharesList(s, policy) # create the shares of the secret s
        w_shares = util.calculateSharesList(w, policy) # create the shares of the w parameter w_x = A_x . w
        s_shares = dict([(x[0].getAttributeAndIndex(), x[1]) for x in s_shares])
        w_shares = dict([(x[0].getAttributeAndIndex(), x[1]) for x in w_shares])
 
        
        rx = []
        w_share = []
        s_share = []
        _attr = []
        for attr, s_sharee in s_shares.items():
            _attr.append(attr)
            w_share.append(w_shares[attr])
            s_share.append(s_sharee)
            rx.append ( group.random() )# for each row of attributes chooses a random r
            


        # For each attribute in discovey policy three values are generated for each of the computational nodes. ---------
        wi = []
        ri = []
        ssi = []
        e = 0
        for attr in s_shares.items():
            wi.append([])
            ri.append([])
            ssi.append([])
            summ_w, summ_r, summ_ss = 0, 0, 0
            for j in range(eta-1):
                wi[e].append(int(group.random() / eta))
                ri[e].append(int(group.random() / eta))
                ssi[e].append(int(group.random() / eta))
                summ_w = summ_w + wi[e][j]
                summ_r = summ_r + ri[e][j]
                summ_ss = summ_ss + ssi[e][j]
            wi[e].append(w_share[e] - summ_w)
            ri[e].append(rx[e] -  summ_r)
            ssi[e].append(s_share[e] - summ_ss)
            e = e + 1
        # -----------------------------------------------------------------------------------------------------------------

        ###############################
        end_time = time.monotonic() # TIME ENDS HERE
        ###############################
        tim1 = timedelta(seconds=end_time - start_time)
        print("End of phase 1")


        # The shares are sent to the computational nodes HERE ############################################################-
        # AT THIS POINT, TO EACH COMPUTATIONAL NODE A SHARE OF S AND A SET OF WJ,RJ AND SSJ FOR EACH ATTRIBUTE ARE SENT.
        # This is done in the computational nodes
        
        egg_s_i = []
        for j in range(eta):
            egg_s_i.append(1)
        
        c1_OUT = []
        c2_OUT = []
        c3_OUT = []
        for j in range(eta):
            c1_OUT.append([])
            c2_OUT.append([])
            c3_OUT.append([])
            for a in range(len(s_shares)):
                k_attr = util.strip_index(_attr[a]) 
                c1_OUT[j].append (1)
                c2_OUT[j].append(1)
                c3_OUT[j].append(1)

        # ##############################################################################################################
        print("End of phase 2")  




        # Assume the shares of the secret have been received from the nodes HERE 
        # A node 0 sends back the following
        # egg_s_i[0] + C1_OUT[0][] + C2_OUT[0][] + C3_OUT[0][] 


        # CHECKING parameters
        #
        #reconstruct_s = 0
        #for j in  range(eta):
        #    reconstruct_s = reconstruct_s + s_i[j]
        # (1) This two values should be the same
        #print("R : ", reconstruct_s)   # Reconstruction of value (s) using the shares
        #print("O : ", s)               # original value of (s)


        ###############################
        start_time = time.monotonic() # TIME STARTS HERE AGAIN
        ###############################
        # Constracting egg_s
        egg_s = 1
        for j in range(eta):
            egg_s = egg_s * egg_s_i[j]
        # (2) This two values shold be the same
        #print(egg_s)
        #print(pair(GP['g'], GP['g']) **  s)
        C0 = M * egg_s
        C1, C2, C3 = {}, {}, {}

        # The shares C1_OUT[0][] + C2_OUT[0][] + C3_OUT[0][] for each attribute from the computational nodes are received from the nodes
        # They are reconstracted HERE
        e = 0
        for attr, s_share in s_shares.items():
            C1[attr], C2[attr], C3[attr] = 1, 1, 1
            for j in range(eta): 
                C1[attr] = C1[attr] * c1_OUT[j][e]
                C2[attr] = C2[attr] * c2_OUT[j][e]
                C3[attr] = C3[attr] * c3_OUT[j][e]
                #a = 3
            e = e + 1
                #print(c1_OUT[attr])

        ###############################
        end_time = time.monotonic() # TIME ENDS HERE
        ###############################
        tim2 = timedelta(seconds=end_time - start_time)    


        # (3) The values of C1, C2 and C3 that are computed through different compuattional nodes should be similar to C1x, C2x and C3x that are calculated locally
        # Uncomment to check.
        #C1x, C2x, C3x = {}, {}, {}
        #a=0
        #for attr, s_share in s_shares.items():
        #    k_attr = util.strip_index(attr)	
        #    w_share = w_shares[attr]
        #    r_x = rx[a] # for each row of attributes chooses a random r
        #    C1x[attr] = (pair(GP['g'],GP['g']) ** s_share) * (pk[k_attr]['e(gg)^alpha_i'] ** r_x)
        #    C2x[attr] = GP['g'] ** r_x
        #    C3x[attr] = (pk[k_attr]['g^beta_i'] ** r_x) * (GP['g'] ** w_share) 
        #    a = a + 1
        #print(C1)
        #print(C1x)

        print("Execution Time (Only for IoT gateway) : ", tim1+tim2)

        return {'C0':C0, 'C1':C1, 'C2':C2, 'C3':C3, 'policy':policy_str} 


def main():   
    groupObj = PairingGroup('SS512')

    attred = attredv1(groupObj)
    GP = attred.setup()
    
    auth1_attrs = ['ONE', 'TWO', 'THREE', 'FOUR', 'FIVE']#, 'SIX', 'SEVEN', 'EIGHT', 'NINE', 'TEN']
    (SK_auth1, PK_auth1) = attred.authsetup(GP, auth1_attrs)
    discovery_policy = '(one or two and three or four and five)'#'((four or three) and (one))' # access policy to IoT resource

    if debug:
        print("Resource Access Policy =>", discovery_policy)
    
    # This section is done by resource registration entity
    rand_key = groupObj.random(GT)
    CT = attred.encrypt(GP, PK_auth1, rand_key, discovery_policy) # Main ABE encryption (of the random key)
if __name__ == "__main__":
    debug = True
    main()
   

