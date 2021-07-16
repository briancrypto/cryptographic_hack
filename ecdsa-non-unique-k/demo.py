# This demonstrate how non-unique k allows attacker to reveal
# one's private key.

import random
import ecdsa
import hashlib
import libnum

#from NIST256p.generator import ecdsa

import logging
logging.basicConfig(level = logging.INFO)
LOG = logging.getLogger('ECDSA-DEMO')

G = ecdsa.NIST256p.generator
order = G.order()

def sign(sk, msg, k):
    
    k = k or random.randrange(1, pow(2,127))
    LOG.info("k is %s"%(k))

    h_msg = int(hashlib.sha256(msg.encode()).hexdigest(), base=16)
    sig = sk.sign(h_msg, k)
    return (sig, h_msg)


# https://www.jcraige.com/dangers-of-determinism-in-threshold-signatures
# r = k * G
# s1 = 1/k (H(msg1) + r * sk)
# s2 = 1/k (H(msg2) + r * sk)
# Solve k
#   s1 - s2 = [ 1/k (H(msg1) + r * sk) ] - [ 1/k (H(msg2) + r * sk) ]
#   s1 - s2 = 1/k [ H(msg1) - H(msg2) ]
#   k = [ H(msg1) - H(msg2) ] / [ s1 - s2 ] % order
# Solve sk
#   s1 = 1/k (H(msg1) + r * sk)
#   sk = (s1 * k ) - H(msg1) / r  % order
def find_sk(data):
    # {'pk': pk, 'sk': sk, 'sig': sig, 'hmsg': hash_of_msg}
    # calculate inverse of (s1 - s2)
    sig_diff = data[0]["sig"].s - data[1]["sig"].s
    inv_sig_diff = libnum.invmod(sig_diff, order)
    k = (data[0]["hmsg"] - data[1]["hmsg"]) * inv_sig_diff % order
    LOG.info("reverse engineer k used: %s"%(k))

    inv_r = libnum.invmod(data[0]["sig"].r, order)
    sk = ((data[0]["sig"].s * k) - data[0]["hmsg"]) * inv_r % order
    LOG.info("reverse engineer sk used: %s"%(sk))

    return (k, sk)

def demo_repeated_k_reveal_sk():

    data = []
    static_k = random.randrange(1, pow(2,127))


    priv = random.randrange(1,order)

    pk = ecdsa.ecdsa.Public_key(G, G * priv)
    sk = ecdsa.ecdsa.Private_key(pk, priv)
    LOG.info("secret key is [%s]"%(priv))

    msg = "blah"
    sig = sign(sk, msg, static_k)
    data.append({'pk': pk, 'sk': sk, 'sig': sig[0], 'hmsg': sig[1]})
    LOG.info("sign message [%s] resulting in signature: [r:%s] [s:%s]"%(msg, sig[0].r, sig[0].s))

    msg = "another random msg"
    sig = sign(sk, msg, static_k)
    data.append({'pk': pk, 'sk': sk, 'sig': sig[0], 'hmsg': sig[1]})
    LOG.info("sign message [%s] resulting in signature: [r:%s] [s:%s]"%(msg, sig[0].r, sig[0].s))

    LOG.info("======= Start to reverse engineer secret key =======")
    (hacked_k, hacked_sk) = find_sk(data)
    if(hacked_k != static_k):
        LOG.info("!!!!!! k reverse engineered is NOT WORKING!")
    
    if(hacked_sk != priv):
        LOG.info("!!!!!! secret key reverse engineered is NOT WORKING!")

if __name__=="__main__":
    demo_repeated_k_reveal_sk()