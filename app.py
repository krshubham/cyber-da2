#!/usr/bin/env python

import getopt
import sys
import math
import __builtin__
import random
import binascii
import struct
import gmpy

from prime_compute import quadratic_residues
from ecc import elgamal_encrypt
from ecc import elgamal_decrypt
from ecc import elliptic_add
from ecc import init_pub_priv_key
from ecc import elliptic_mul
from ecc import elliptic_add


def generate_keys(curve, prime, name):
    f=open("."+name+"_private_key", 'w')
    private_key=random.randint(1, prime/1000)
    f.write("----BEGIN APG PRIVATE KEY BLOCK----\n")
    f.write(str(private_key))
    f.close()
    alpha_x, alpha_y, beta_x, beta_y=init_pub_priv_key(curve, prime, private_key)
    f2=open(name+".asc", 'w')
    f2.write("----BEGIN APG PUBLIC KEY BLOCK----\n")
    f2.write(str(alpha_x)+"/")
    f2.write(str(alpha_y)+"/")
    f2.write(str(beta_x)+"/")
    f2.write(str(beta_y))
    f2.close()
    
def read_public_key(name):
    f=open(name+".asc", 'r')
    f.readline()
    array=f.readline().split("/")
    alpha_x=array[0]
    alpha_y=array[1]
    beta_x=array[2]
    beta_y=array[3]
    return (long(alpha_x), long(alpha_y), long(beta_x), long(beta_y))

def read_private_key(name):
    f=open("."+name+"_private_key", 'r')
    f.readline()
    pk= long(f.readline())
    f.close()
    return pk

def is_point((x,y), curve, prime):
    if (__builtin__.pow(y,2,prime)%prime)==((__builtin__.pow(x,3,prime)+curve[0]*x+curve[1])%prime):
        return True
    else:
        return False

#computes x value on the curve
def encode_message(m,curve, prime):
    #give us a 1/2^20 chance of failure
    encoded=20*m
    for i in range(20):
        if is_quadratic_residue(long(eval_function(encoded, curve,prime))%prime, prime):
            break
        encoded=encoded+1
    y=quadratic_residues(long(eval_function(encoded,curve, prime))%prime, prime)
    return (encoded, y[0])

def decode_message(x,K):
    return x/K

#compute f(x)
def eval_function(x, f, prime):
    return __builtin__.pow(x,3, prime)+f[0]*x+f[1]


#returns 1 if x is a quadratic residue mod n, 0 elsewise
#uses Euler's theorem
def is_quadratic_residue(x,n):
    # modular exponentiaion, as opposed to maths pow function. Otherwise we get an overflow
    ret=__builtin__.pow(x,(n-1)/2,n)
    if ret==1:
        return True 
    else: 
        return False

def main():
    blocks=[]
    block=[]
    #NIST P-256
    prime=115792089210356248762697446949407573530086143415290314195533631308867097853951
    #our elliptic curve,y^2=x^3+bx+c, where curve=[b,c]
    curve=[115792089210356248762697446949407573530086143415290314195533631308867097853948, 41058363725152142129326129780047268409114441015993725554835256314039467401291]
    #don't modify
    block_length=24
    out_file=None
    decrypt_name=None
    encrypt_flag=False
    encrypt_name=None
    decrypt_flag=False
    recipient=None
    user=None
    args=sys.argv[1:]

    try:
        optlist, args=getopt.getopt(args,'e:g:f:o:r:d:u:')
    except getopt.GetoptError as err:
        print str(err)
        sys.exit(2)
    for opt, arg in optlist:
        #generate public and private keys
        if opt=="-g":
            generate_keys(curve, prime, arg)
            return 0
        #specify output file
        if opt=="-o":
            out_file=arg
        #encrypt flag
        if opt=="-e":
            encrypt_name=arg
            encrypt_flag=True
        if opt=="-r":
            recipient=arg
        if opt=="-d":
            decrypt_flag=True
            decrypt_name=arg
        if opt=="-u":
            user=arg

    if encrypt_flag==True:
        #parse file
        f_encrypt_name=open(encrypt_name,"rb")
        points=[]
        i=0
        while True:
            c=f_encrypt_name.read(1)
            if not c:
                if i!=0:
                    #flush buffer
                    blocks.append(block)
                break
            block.append(c)
            i=i+1
            if i==block_length:
                blocks.append(block)
                i=0
                block=[]
        for a in blocks:
        #    a[0:]=map(ord,a[0:]);
            a[0:]=map(lambda x: int(binascii.hexlify(x), 16),a[0:])
        for a in blocks:
            val=reduce(lambda x,y: 1000*x+y,a,0)
            points.append(val)

        #encrypt
        alpha_x, alpha_y, beta_x, beta_y=read_public_key(recipient)
        points=map(lambda x: encode_message(x, curve, prime), points)
        cipher_text=[]
        for p in points:
            cipher_text.append(elgamal_encrypt((p[0],p[1]), curve, prime, (alpha_x, alpha_y), (beta_x, beta_y)))
        f_out=open(out_file, 'w')
        f_out.write("-----BEGIN AGP MESSAGE-----\n")
        for ci in cipher_text:
             f_out.write(str(ci[2])+"/")
             f_out.write(str(ci[3])+"/")
             f_out.write(str(ci[0])+"/")
             f_out.write(str(ci[1])+":")
        f_out.close()
        print(encrypt_name+" encrypted to "+out_file)
        return 0

    if decrypt_flag==True:
        private_key=read_private_key(user)
        f_in=open(decrypt_name,'r')
        f_in.readline()
        s=f_in.readline()
        s=s.split(":")
        s.pop()
        c_texts=[]
        for c_points in s:
            c_texts.append(c_points.split("/"))
        #print s
       # print c_texts
        plain_points=[]
        for ci in c_texts:
            plain_points.append(elgamal_decrypt((long(ci[0]),long(ci[1])), (long(ci[2]), long(ci[3])), curve, prime, private_key))
        decoded=[]
        for p in plain_points:
            decoded.append(decode_message(p[0], 20))
        plain_text=[]
        for x in decoded:
            seg=[]
            while x!=0:
                seg.insert(0,x%1000)
                x/=1000
            plain_text.append(seg)
        out_bytes=[]
        for x in xrange(len(plain_text)):
#            plain_text[x]="".join(map(lambda x: chr(x), plain_text[x]))
             for y in plain_text[x]:
                 out_bytes.append(y)
#        plain_text="".join(plain_text)
        outf=open(out_file,"wb")
        for x in out_bytes:
            if x>127:
                outbyte=x-256
            else:
                outbyte=x
            outf.write(struct.pack('b',outbyte))
#        outf.write(plain_text)
        print(decrypt_name+" decrypted to "+out_file)
        outf.close()
        return 0

if __name__=="__main__":
    main()
