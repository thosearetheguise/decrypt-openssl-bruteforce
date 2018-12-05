#!/usr/bin/env python
# -*- coding: utf-8 -*-

import subprocess
import sys
import os
import argparse

PWD = os.getcwd()

green = "\033[1;32;40m"
normal = "\033[0;37;40m"

def cmdline(command):
    proc = subprocess.Popen(str(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()
    return err

def str2bool(v):
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Bool (true/false) value expected.')

def main():

    if (len(sys.argv) > 1):

        parser = argparse.ArgumentParser()

        parser = argparse.ArgumentParser(description='decrypt-openssl-bruteforce performs dictionary attacks against openssl encrypted files saving the plain text file locally')
        requiredNamed = parser.add_argument_group('required named arguments')
        requiredNamed.add_argument("-i","--infile", help="Path to the encrypted file.",required=True)
        requiredNamed.add_argument("-w","--wordlist", help="Path to the wordlist file",required=True)
        requiredNamed.add_argument("-o","--outfile", help="Path of the plain text output if decrypted.",required=True)
        optionalNamed = parser.add_argument_group('optional arguments')
        optionalNamed.add_argument("-c","--cipher",nargs='?', help="Any openssl supported cipher including leading - (openssl enc -ciphers) default: -aes256",default="-aes256")
        optionalNamed.add_argument("-s","--salted",type=str2bool, nargs='?', const=True, default=False, help="Data is encrypted with salt (openssl enc'd data with salted password) default: False")
        optionalNamed.add_argument("-b64","--base64",type=str2bool, nargs='?', const=True, default=False, help="Data is Base64 encoded. Default: False")
        optionalNamed.add_argument("-v","--verbose",type=str2bool, nargs='?', const=True, default=False, help="Verbose output, output all passwords atempted. Default: False")
        optionalNamed.add_argument("-vv","--veryverbose",type=str2bool, nargs='?', const=True, default=False, help="Very Verbose output, also output the openssl commands executed, (includes -v). Default: False")

        args = parser.parse_args()
        salted = args.salted
        b64 = args.base64
        verbose = args.verbose
        veryverbose = args.veryverbose
        if veryverbose:
            verbose = veryverbose
        encryptedfile = args.infile
        wordlist = args.wordlist
        cipher = args.cipher
        print("Optional argument values:\nSalted:{} \nbase64:{} \ncipher:{}".format(salted, b64,cipher))
        outputfile = args.outfile

        with open(wordlist) as f:
            line = f.readline()
            count = 1
            while line:
                line = line.strip()
                if len(line) > 0:
                    if verbose:
                        print("Trying password: {}".format(line))
                    cmd = "openssl enc -d {}".format(cipher) +['',' -base64'][b64] + ['',' -salt'][salted] + " -in {} -out {} -k {}".format(encryptedfile,outputfile,line)
                    if veryverbose:
                        print("Full command: {}".format(cmd))
                    if b"bad decrypt" not in cmdline(cmd):
                        print(green+"\nKey Found! The key is:{}".format(line))
                        print(normal+"Output File Name : {}".format(outputfile))
                        sys.exit()
                line = f.readline()
                count += 1
        print("\n")

    else:
        print ("Usage {} [-h] -i ENCRYPTEDFILE -w WORDLIST -o OUTFILE \n[-c CIPHER] [-s SALTED] [-b64 BASE64DECODE]".format(sys.argv[0]))
if __name__ == '__main__':
    main()

