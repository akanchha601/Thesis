import pandas as pd
import glob,os
import ssl,socket
import OpenSSL.crypto as crypto
from cryptography.hazmat._oid import ObjectIdentifier
from asn1crypto.x509 import Certificate
import csv
from OpenSSL.crypto import (load_certificate, dump_privatekey, dump_certificate, X509, X509Name, PKey)
from datetime import datetime
import numpy as np 


#read Domains from a CSV file
def readURL(url):
    try:
		url = r "path of csv file"
		names = ['url', 'class']
		dataset = pd.read_csv(url,names = names)
		df = pd.DataFrame(dataset)
		cols = [0]
		df = df[df.columns[cols]]
	except IOError:
		print "Could not open and read file:"
		sys.exit()
	finally:
        print "exit"	
    return dataset

#Extracting SSL Certificates from the Domains
def readDomain():
	x509=[]
	dataset=read_URL(url)
	for host in dataset['url']:
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		except socket.error:
			return "Error in socket connection"
		except ValueError:
			return "Please enter valid site name"    
		try:
			s.connect(dst)
		except socket.gaierror:
			return "Address-related error connecting to server" 
			sys.exit(1)
		except socket.error:
			return "Connection error" % e
		except ValueError:
			return "Please enter valid site name" 
		ctx = ssl.create_default_context()
		ctx.check_hostname = False
		ctx.verify_mode = ssl.CERT_NONE
		s = ctx.wrap_socket(s, server_hostname=dst[0])
		certificate = ssl.DER_cert_to_PEM_cert(s.getpeercert(True))
		x509_2.append(certificate)
	zipbObj_1=zip(x509_2)   
    return zipbObj_1
	
#Write SSL Certificates in a CSV file	
def writeCert(zipbObj_1):
    zipbObj_1=readDomain()
    try:	
		with open(r'path of csv file', 'w') as output:
			writer = csv.writer(output, lineterminator='\n')
			writer.writerows(zipbObj_1)
    except OSError:
		print "Could not open and write file:"
		sys.exit()
    finally:
        print "exit"		