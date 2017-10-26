#functions for encrypting and decrypting with elgamal using elliptic curves

#the elliptic curve, the prime modulus, our starting point alpha, and beta=alpha*the private key make up the public key that we are encrypting with

import __builtin__
import random
import math

from prime_compute import modinv

#create a public and private key pair consisting of an initial point alpha, beta = initial point*secret key and a secret key
def init_pub_priv_key(curve, prime,private_key):
    alpha_x=48439561293906451759052585252797914202762949526041747995844080717082404635286
    alpha_y=36134250956749795798585127919587881956611106672985015071877198253568414405109
#    for i in range(private_key-1):
#        (beta_x, beta_y)=elliptic_add((beta_x, beta_y),(alpha_x,alpha_y), curve, prime)
    beta_x, beta_y=elliptic_mul((alpha_x,alpha_y), private_key, curve, prime)
    return (alpha_x, alpha_y, beta_x, beta_y)
    
#takes our message as an argument in the form of a point
def elgamal_encrypt((m_x,m_y), curve, prime, (alpha_x,alpha_y), (beta_x,beta_y)):
    #alpha is our initial point on the curve
    #k is our random integer, must be different every time or an eavesdropper who discovers one plaintext can discover all other plaintexts
    k=random.randint(1,prime-1)
    #create p1=k*alpha
    x1=alpha_x
    y1=alpha_y
#    for i in range(k-1):
#        (x1,y1)=elliptic_add((x1,y1),(alpha_x,alpha_y), curve, prime)
    x1, y1=elliptic_mul((x1, y1), k, curve, prime)
    #compute p2=k*beta
    x2=beta_x
    y2=beta_y
#    for i in range(k-1):
#        (x2,y2)=elliptic_add((x2,y2),(beta_x,beta_y), curve, prime)
    x2, y2= elliptic_mul((x2, y2), k, curve, prime)
    #compute cipher=m+p2
    (cipher_x,cipher_y)=elliptic_add((x2,y2),(m_x,m_y), curve, prime)
    return (x1,y1,cipher_x,cipher_y)

#returns derypted message in form of a point
def elgamal_decrypt((cipher_x, cipher_y), (enc_x, enc_y), curve, prime, private_key):
    x1=enc_x
    y1=enc_y
#    for i in range(private_key-1):
#        (x1, y1)=elliptic_add((enc_x, enc_y), (x1, y1), curve, prime)
    x1, y1=elliptic_mul((x1, y1), private_key, curve, prime)
    #compute answer
    x2=cipher_x
    y2=cipher_y
    (x2, y2)=elliptic_add((cipher_x, cipher_y), (x1, -y1), curve, prime)
    return (x2, y2)

#elliptic curve point addition
# returns None, representing infinity (the abelian group's identity), if two inverses are added
def elliptic_add((x1, y1),(x2,y2),curve, prime):
    # p1 and p2 are inverses
    if ((x1==x2)and(y1!=y2)):
        return (None, None)
    #corner case where y1==y2==0
    if ((x1==x2)and(y1==0)and(y2==0)):
        return (None, None)
    # definition of identity
    if (x1 is None):
        return (x2, y2)
    if (x2 is None):
        return (x1, y1)
    
    #m is tangent slope
#    if (modinv(((2*y1)%prime), prime)) is None:
#        print x1, y1, x2, y2
    if ((x1==x2)and(y1==y2)):
        m=(((3*__builtin__.pow(x1,2, prime)+curve[0])%prime)*modinv(((2*y1)%prime), prime))%prime
    else:
        m=((y2-y1)%prime)*modinv((x2-x1)%prime,prime)
    x3=(__builtin__.pow(m,2,prime)-x1-x2)%prime
    y3=(m*(x1-x3)-y1)%prime
    return (long(x3), long(y3))

#need elliptic curve equivalent of successive squaring in order to complete in reasonable amount of time. We are working with an abelian group so this is allowable
def elliptic_mul((x, y), n, curve, prime):
    if n==0:
        return (None, None)
    if n==1:
        return (x, y)
    elif (n%2)==1:
        return elliptic_add((x, y), elliptic_mul((x,y), n-1, curve, prime), curve, prime)
    else:
        return elliptic_mul(elliptic_add((x, y),(x,y), curve, prime), n/2, curve, prime)
