import __builtin__
import math

#use Euler's criterion
def legendre(n, p):

    #when p is prime, and a is a quadratic resude mod p, the legendre symbol =1, equals -1 otherwise
    leg = __builtin__.pow(n, (p-1)/2, p)
    
    #same as being congurent to -1 mod p
    if(leg%p) == (p-1):
        return -1
    return leg

#program ensures than n is a quadratic residue
#compute quadratic residues using Tonelli Shanks algorithm if they exist
def quadratic_residues(n, p):

    n=n%p
    # Factor out powers of 2 from p-1, defining Q and S as: p-1=Q2^S with Q odd
    q=p-1
    s=0
    while (q%2)==0:
        q/=2
        s+=1

    #Select a z such that the Legendre symbol(z/p)=-1 (that is, z should be a quadratic non-residue modulo p), and set c congruent to z^Q
    z= 2
    while legendre(z, p)!=-1:
        z+=1
    c=__builtin__.pow(z, q, p)

    # let r=n((q+1)/2), t congruent to n^q, m=s
    r=__builtin__.pow(n, (q+1)/2, p)
    t=__builtin__.pow(n, q, p)
    m=s

    while t!=1:
        # Find the lowest i, 0<i<M, such that t^(2^i) is congruent to 1, via repeated squaring
        t_exp=2
        for i in xrange(1, m):
            if __builtin__.pow(t, e, p)==1:
                break
            t_exp*=2

        b=__builtin__.pow(c, 2**(m - i - 1), p)
        r=(r*b)%p
        t=(t*__builtin__.pow(b,2,p))%p
        c=__builtin__.pow(b,2,p)%p
        m=i
    return [r, p-r]

def egcd(a, b):
    if a==0:
        return (b, 0, 1)
    else:
        g, y, x =egcd(b%a, a)
        return (g, x-(b//a)*y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g!=1:
        #no modular inverse if gcd!=1
        return None
    else:
        return x%m
