"""
TOUFAS KONSTANTINOS
AEM: 2416
S-DES Encryption Algorithm
"""

import sys
import argparse

"""
This is the initial permutation function. IP
"""
def ip(pt):
    temp = list(pt)
    temp[0]=pt[1]
    temp[1]=pt[5]
    temp[2]=pt[2]
    temp[3]=pt[0]
    temp[4]=pt[3]
    temp[5]=pt[7]
    temp[6]=pt[4]
    temp[7]=pt[6]
    return ''.join(temp)


#This is the inverse initial permutation fuction. IP^(-1)

def ipInverse(pt):
    temp = list(pt)
    temp[0]=pt[3]
    temp[1]=pt[0]
    temp[2]=pt[2]
    temp[3]=pt[4]
    temp[4]=pt[6]
    temp[5]=pt[1]
    temp[6]=pt[7]
    temp[7]=pt[5]
    return ''.join(temp)


#This is P10 permutation function

def pTEN(key):
    tmp = list(key)
    tmp[0]=key[2]
    tmp[1]=key[4]
    tmp[2]=key[1]
    tmp[3]=key[6]
    tmp[4]=key[3]
    tmp[5]=key[9]
    tmp[6]=key[0]
    tmp[7]=key[8]
    tmp[8]=key[7]
    tmp[9]=key[5]
    return ''.join(tmp)
#This is the P8 permutation function
def pEIGHT(key):
    tmp = list(key)
    tmp[0]=key[5]
    tmp[1]=key[2]
    tmp[2]=key[6]
    tmp[3]=key[3]
    tmp[4]=key[7]
    tmp[5]=key[4]
    tmp[6]=key[9]
    tmp[7]=key[8]
    return ''.join(tmp[:8])

#This is the P4 permutation function
def pFOUR(key):
    tmp = '{}{}{}{}'.format(key[1],key[3],key[2],key[0])
    return tmp

#This is the shift left by one bit function. LS-1
def lsONE(key):
    ls1 = '{}{}{}{}{}'.format(key[1],key[2],key[3],key[4],key[0])
    ls2 = '{}{}{}{}{}'.format(key[6],key[7],key[8],key[9],key[5])
    return ls1+ls2

#This is the shift left by 2 bits function. LS-2
def lsTWO(key):
    ls1 = '{}{}{}{}{}'.format(key[2],key[3],key[4],key[0],key[1])
    ls2 = '{}{}{}{}{}'.format(key[7],key[8],key[9],key[5],key[6])
    return ls1+ls2

#This is the expansion permutation function
def eXp(fBits):
    ep = [fBits[3],fBits[0],fBits[1],fBits[2],fBits[1],fBits[2],fBits[3],fBits[0]]
    return ''.join(ep)

#This is the bit-by-bit XOR function.
def bitXOR(bitsA, bitsB):
    r = ""
    for i in range(len(bitsA)):
        if bitsA[i]!=bitsB[i]:
            r += "1"
        else:
            r+= "0"
    return r
#This is the SW function. Swaps the first half of the input for the second half and vice versa.
def sw(iput):
    switched = '{}{}{}{}{}{}{}{}'.format(iput[4],iput[5],iput[6],iput[7],iput[0],iput[1],iput[2],iput[3])
    return switched
#This if the F(R,Key) function
def f(half, key):
    sBOX0 = [['01','00','11','10'],['11','10','01','00'],['00','10','01','11'],['11','01','11','10']] #S-BOX 0
    sBOX1 = [['00','01','10','11'],['10','00','01','11'],['11','00','01','00'],['10','01','0','11']] #S-BOX 1
    ep = eXp(half) #Expansion permutation of R
    xr = bitXOR(ep, key) #Bit-by-bit XOR between the half nibble (R) and the key 
    xr_s0 = xr[:4] #Left half of XOR result
    xr_s1 = xr[4:] #Right half of XOR result
    s0_r = int(xr_s0[0]+xr_s0[3],2) #CHOOSE ROW FOR SBOX0
    s0_c = int(xr_s0[1]+xr_s0[2],2) #CHOOSE COLUMN FOR SBOX0
    sbz = sBOX0[s0_r][s0_c] #TAKE RESULT FROM SBOX0
    s1_r = int(xr_s1[0]+xr_s1[3],2)  #CHOOSE ROW FOR SBOX1
    s1_c = int(xr_s1[1]+xr_s1[2],2) #CHOOSE COLUMN FOR SBOX1
    sbo = sBOX1[s1_r][s1_c] #TAKE RESULT FROM SBOX1
    sbOPuts = sbz+sbo #Join S-BOX outputs
    f = pFOUR(sbOPuts) #P4(joined S-BOX results)
    return f #F(R,Key) Result

#Encryption function. Ciphertext = IP^-1(fk2(SW(fk1(IP(plaintext)))))
def encrypt(msg, key):
    permuted = ip(msg) #Initial Permutation
    k1=pEIGHT(lsONE(pTEN(key))) #First Key (K1)
    k2=pEIGHT(lsTWO(lsONE(pTEN(key)))) #Second Key(K2)
    ipR = permuted[4:] #Right half nibble (R) of IP(Message)
    fK1 = f(ipR,k1) #RESULT OF F(R, K1)
    ipL = permuted[:4]  #Left half nibble (L) of IP(Message)
    lXf = bitXOR(ipL,fK1) #L XOR F(R, K1)
    newIP = lXf+permuted[4:]#Replace left half of IP
    swH = sw(newIP) #SW(fk1(IP(plaintext)))
    swR = swH[4:] #Right half nibble of SW result
    fK2 = f(swR,k2) #Result of F(R,K2)
    swL = swH[:4] #Left half nibble of SW
    swLXf = bitXOR(swL,fK2) #L XOR F(R, K2)
    final = swLXf + swR #Replace Left hafl of SW
    cipher = ipInverse(final) #IP^-1
    return cipher
#Decrypt is the inversed ecrypt function
def decrypt(eMsg, key):
    permuted = ip(eMsg)
    k1=pEIGHT(lsONE(pTEN(key)))
    k2=pEIGHT(lsTWO(lsONE(pTEN(key))))
    ipR = permuted[4:]
    fK2 = f(ipR,k2) #RESULT OF F(R, K1)
    ipL = permuted[:4]
    lXf = bitXOR(ipL,fK2) #L XOR F(R, K1)
    newIP = lXf+permuted[4:]#Replace left half of IP
    swH = sw(newIP)
    swR = swH[4:]
    fK1 = f(swR,k1)
    swL = swH[:4]
    swLXf = bitXOR(swL,fK1)
    final = swLXf + swR
    plainT = ipInverse(final)
    return plainT
    

#-----------------MAIN-----------------------
def main():
	if len(sys.argv) != 4:
	    print("Usage: sdes.py [8-bit Message] [10-bit Key] [-E (Encrypt) or -D (Decrypt)]")
	elif len(sys.argv[1])!=8:
	    print("The size of the message must be 8 bits")
	elif len(sys.argv[2])!=10:
	    print("The size of the key must be 10 bits")
	elif sys.argv[3]!="-E" and sys.argv[3]!="-D":
	    print("Please type -E for Encryption or -D for Decryption")
	else:
	    message = sys.argv[1] #Plaintext
	    kEY = sys.argv[2] #Key
	    action = sys.argv[3] #-E for encryption OR -D for decryption
	    execute = True
	    for b in message:
	        if b!="0" and b!="1":
	            print("Message must be a binary string")
	            execute = False
	            break
	    for b in kEY:
	        if b!="0" and b!="1":
	            print("Key must be a binary string")
	            execute = False
	            break
	    if execute:
	        if action=="-E":
	            ciph = encrypt(message,kEY)
	            print("Cipher: "+ ciph)
	        else:
	            plaint = decrypt(message,kEY)
	            print("Decrypted Message: " + plaint)

if __name__ == '__main__':
	main()
	        
    
    
    
    