import pandas as pd
import glob,os
import ssl,socket
import OpenSSL.crypto as crypto
from cryptography.hazmat._oid import ObjectIdentifier
from asn1crypto.x509 import Certificate
from cryptography.hazmat.backends import default_backend
import csv
from OpenSSL.crypto import (load_certificate, dump_privatekey, dump_certificate, X509, X509Name, PKey)
from datetime import datetime
import numpy as np 
import array as arr
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import euclidean_distances
import pickle
import copy_reg
from publicsuffix2 import PublicSuffixList
import seolib
from sklearn.metrics import mutual_info_score
from sklearn.feature_extraction.text import CountVectorizer
from scipy.stats import kstest,norm
from scipy.stats import ks_2samp
from IPy import IP
from sets import Set
import urllib, sys, bs4
import math

#reading SSL Certificates from a CSV file
def readCert():
	x509=[]
	with open(r'path') as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=' ')
		for row in csv_reader:
			x509.append(crypto.load_certificate(crypto.FILETYPE_PEM, row[0]))
    return x509
	
# Indicates if CN is an IP address instead of domain
def subjectCommonNameIP():
    x509 = readCert()
	SubjectCommonNameIp = []
	for cert in x509:
		str=cert.get_subject().CN
		def isIP(str):
			try:
				IP(str)
			except ValueError:
				return False
			return True
		SubjectCommonNameIp.append(isIP(str))   
    return SubjectCommonNameIp
	

def typeOfCertificate():
	typeOfCertificate_validated = []
    x509 = readCert()
	for cert in x509:
		validated = False
		#Indicates if certificate is extended validated
		if cert.get_subject().businessCategory:
						   validated = True 
        #Indicates if certificate is organization validated
		elif cert.get_subject().O:
						   validated = True
		#Indicates if certificate is domain validated		
		else:
			  validated = True
		typeOfCertificate_validated.append(p) 
	return typeOfCertificate_validated

def subjectOnlyCN():
	Subject_onlyCN=[]
	x509 = readCert()
	onlyCN=False
	if (not x509.get_subject().O and not x509.get_subject().OU and not x509.get_subject().L and not x509.get_subject().ST and not x509.get_subject().C and not x509.get_subject().businessCategory):
		onlyCN=True
	else:
		onlyCN=False
    return Subject_onlyCN

#Indicates if subject principal has O field
def subjectHasOrganization():
    x509 = readCert()
	SubjectHasOrganization =[]
	a=False
	for cert in x509:
		if cert.get_subject().O:
			a=True
		else:
			a=False
	return SubjectHasOrganization

# Indicates if issuer principal has O field	
def issuerHasOrganization():
    x509 = readCert()
	IssuerHasOrganization=[]
	b=False
	for cert in x509:      
		if cert.get_issuer().O:
			b=True
		else:
			b=False    
		IssuerHasOrganization.append(b)
	return IssuerHasOrganization
	
# Indicates if subject principal has CO field

def subjectHasCompany():
    x509 = readCert()
	SubjectHasCompany=[]
	c=False
	for cert in x509:
		if cert.get_subject().C:
			c=True
		else:
			c=False      
		SubjectHasCompany.append(c)
	return SubjectHasCompany

# Indicates if issuer principal has CO field
def issuerHasCompany():
	IssuerHasCompany=[]
	x509 = readCert()
	d=False
	for cert in x509:
		if cert.get_issuer().C:
			d=True
		else:
			d=False    
		IssuerHasCompany.append(d) 
	return IssuerHasCompany
	
# Indicates if subject principal has ST field

def subjectHasState():
	SubjectHasState=[]
	e=False
	x509 = readCert()
	for cert in x509:
		if cert.get_subject().ST:
			e=True
		else:
			e=False
		SubjectHasState.append(e)
	return SubjectHasState

#Indicates if issuer principal has ST field	
def issuerHasState():
	IssuerHasState=[]
	x509 = readCert()
	f=False
	for cert in x509:    
		if cert.get_issuer().ST:
			f=True
		else:
			f=False   
		IssuerHasState.append(f) 
	return IssuerHasState
	
#Indicates if subject principal has L field

def subjectHasLocation():
	SubjectHasLocation=[]
	x509 = readCert()
	g=False
	for cert in x509:
		if cert.get_subject().L:
			g=True
		else:
			g=False    
		SubjectHasLocation.append(g)
	return subjectHasLocation

#Indicates if issuer principal has L field
def issuerHasLocation():
	IssuerHasLocation=[]
	x509 = readCert()
	h=False
	for cert in x509:
		if cert.get_issuer().L:
			h=True
		else:
			h=False    
		IssuerHasLocation.append(h) 
	return IssuerHasLocation
	
#Indicates if subject CN is a ”.com” domain
def subjectiscom():
	psl = PublicSuffixList(idna=True)
	x509 = readCert()
	Subject_is_com=[]
	for cert in x509:
		i= False
		j= 'com'
		if j in psl.get_tld(cert.get_subject().CN):
				 i = True
		else:
				 i=False		 
		Subject_is_com.append(i)
	return Subject_is_com

#Indicates if issuer CN is a ”.com” domain	
def issueriscom():
	psl = PublicSuffixList(idna=True)
	x509 = readCert()
	Issuer_is_com=[]
	for cert in x509:
		k= False
		j= 'com'
		if j in psl.get_tld(cert.get_issuer().CN):
				 k = True
		else:
				 k=False
		Issuer_is_com.append(k)
	return Issuer_is_com
	
#Indicates if CN is present in subject principal
#Indicates if CN is present in issuer principal

def subissCommonName():
    x509 = readCert()
    HasSubjectCommonName=[]
    HasIssuerCommonName=[]
    for cert in x509:
		if cert.get_subject().CN:
			m=True
		else:
			m=False
		HasSubjectCommonName.append(m)    
		if cert.get_issuer().CN:
			n=True
		else:
			n=False    
		HasIssuerCommonName.append(n)
	return HasSubjectCommonName,HasIssuerCommonName
	
#Boolean indicating if Subject Principal = Issuer Principal
def subjecteqIssuer():
    x509 = readCert()
	Subject_eq_Issuer=[]
	for cert in x509:
	    if (cert.get_subject()== cert.get_issuer()):
					o= True
		else:
			 o= False
		Subject_eq_Issuer.append(o)
	return 	Subject_eq_Issuer
	
def subIssLength():
    x509 = readCert()
	SubjectElements=[]
	IssuerElements=[]
	SubjectLength=[]
	IssuerLength=[]
	ExtensionNumber=[]
	for cert in x509:   
		subject = []
		issue = cert.get_issuer()
		sub= cert.get_subject()
		issuer = []
		for item in issue.get_components():
				issuer.append('%s' %  (item[1]) )
		for item in sub.get_components():
				subject.append('%s' %  (item[1]) )
		total=0
		total1=0
		for word in subject:
			total += len(str(word))
		
		for word in issuer:
			total1 += len(str(word))
		SubjectElements.append(len(subject))
		IssuerElements.append(len(issuer))
		SubjectLength.append(total)
		IssuerLength.append(total1)
		ExtensionNumber.append(cert.get_extension_count())
		        
	return 	SubjectElements,IssuerElements, SubjectLength, IssuerLength,ExtensionNumber
	

#Indicates if the certificate is self signed
def selfSigned():
    x509 = readCert()
	Selfsigned=[]
    for cert in x509:
		k=False
		if ((cert.get_subject().O== cert.get_issuer().O) and (cert.get_subject().OU== cert.get_issuer().OU) and (cert.get_subject().L== cert.get_issuer().L) and
		(cert.get_subject().ST== cert.get_issuer().ST) and (cert.get_subject().C== cert.get_issuer().C) or (cert.get_subject().CN== cert.get_issuer().CN)):
			k=True
		Selfsigned.append(k)
	return	Selfsigned

#Indicates if the certificate is free generated
def isFree():
	Is_free=[]
	free=False
	x509 = readCert()
	for cert in x509:
		a = datetime.strptime(cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
		b = datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
        q=abs((b-a).days)
		if not cert.get_subject().O:
			if not cert.get_subject().businessCategory:
						if q<=90:
							free=True
						else:
							free=False
				
			else:
				  free=False
		else:
			free=False
		Is_free.append(free)
	return Is_free
	
#Calculated days between not before and not after days
def daysValidity():
    DaysValidity=[]
	x509 = readCert()
    for cert in x509:
		a = datetime.strptime(cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
		b = datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
        z=abs((b-a).days)
		DaysValidity.append(z)
	return DaysValidity

#Domain ranking
def domainRanking():
	Domain_ranking=[]
	for host in dataset['url']:
		if seolib.get_alexa('https://'+host):
			Domain_ranking.append(seolib.get_alexa('https://'+host))
		else:
			Domain_ranking.append(None)
	return Domain_ranking

#Calculated character entropy in the subject CN
def entropyCommonName():
	Entropy=[]
	x509 = readCert()
	for cert in x509:  
		st = cert.get_subject().CN
		
		stList = list(st)
	  
		alphabet = list(Set(stList)) 
		
		freqList = []
		for symbol in alphabet:
			#print(symbol)
			ctr = 0
			for sym in stList:
				if sym == symbol:
					ctr += 1
			freqList.append(float(ctr) / len(stList))
		   # Shannon entropy
		ent = 0.0
		for freq in freqList:
			ent = ent + freq * math.log(freq, 2)
		ent = -ent
		Entropy.append(ent)	
    return Entropy
	
def commonName():
	SubjectCommonName=[]
	IssuerCommonName=[]
	x509 = readCert()
	for cert in x509:
		  SubjectCommonName.append(cert.get_subject().CN)
		  IssuerCommonName.append(cert.get_issuer().CN)
    return SubjectCommonName,IssuerCommonName

# Calculated euclidean distance of subject among all subjects	
def euclidianSubjectandSubjects():
    Euclidian_Subject_Subjects=[]
    vectorizer = TfidfVectorizer()
	SubjectCommonName,IssuerCommonName=commonName()
    # tokenize and build vocab
	features=vectorizer.fit_transform(SubjectCommonName).todense()
	for f in features :
		x=euclidean_distances(features[0],f)
		ed=np.array(x[0])
		Euclidian_Subject_Subjects.append(ed[0])
	return Euclidian_Subject_Subjects
	
#Calculated euclidean distance of subject characters among English characters
def euclidianSubjectEnglish():
    SubjectCommonName,IssuerCommonName=commonName()
	Euclidian_Subject_English=[]
	tfidf_vectorizer = TfidfVectorizer(analyzer='char',lowercase=False)
	tfidf_matrix_train = tfidf_vectorizer.fit_transform(SubjectCommonName)
	tfidf_matrix_test = tfidf_vectorizer.transform(["abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"])
    a = euclidean_distances(tfidf_matrix_train,tfidf_matrix_test)
	for value in a:
		Euclidian_Subject_English.append(value[0])
	return Euclidian_Subject_English

#Calculated euclidean distance of issuer among all issuers	
def euclidianIssuerandIssuers():
	Euclidian_Issuer_Issuers=[]
	SubjectCommonName,IssuerCommonName=commonName()
	vectorizer = TfidfVectorizer()
	# tokenize and build vocab
	features=vectorizer.fit_transform(IssuerCommonName).todense()
	for f in features :
		x=euclidean_distances(features[0],f)
		ed=np.array(x[0])
		Euclidian_Issuer_Issuers.append(ed[0])
	return Euclidian_Issuer_Issuers

#Calculated euclidean distance of issuer characters among English characters
def euclidianIssuerEnglish():
	Euclidian_Issuer_English=[]
	SubjectCommonName,IssuerCommonName=commonName()
	tfidf_vectorizer = TfidfVectorizer(analyzer='char',lowercase=False)
	tfidf_matrix_train = tfidf_vectorizer.fit_transform(IssuerCommonName)
	tfidf_matrix_test = tfidf_vectorizer.transform(["abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"])
    a = euclidean_distances(tfidf_matrix_train,tfidf_matrix_test)
	for value in a:
		Euclidian_Issuer_English.append(value[0])
	print(Euclidian_Issuer_English)
	
#Kolmogorov-Smirnov statistics for subject in subjects
def kolmogorovSubjectandSubjects():
    SubjectCommonName,IssuerCommonName=commonName()
	Ks_stats_Subject_Subjects=[]
    vectorizer = TfidfVectorizer()
	features=vectorizer.fit_transform(SubjectCommonName).todense()
	for f in features :
		Ks_stats_Subject_Subjects.append(kstest(f,'norm').statistic)
	return Ks_stats_Subject_Subjects
	
#Kolmogorov-Smirnov statistic for subject in English characters
def kolmogorovSubjectEnglish():
	Ks_stats_Subject_English=[]
	SubjectCommonName,IssuerCommonName=commonName()
	vectorizer_vector_ks_sub_cn = CountVectorizer(analyzer='char',lowercase=False)
	vectorizer_vector_ks_sub_cn.fit(SubjectCommonName)
    vector_ks_sub_cn = vectorizer_vector_ks_sub_cn.transform(SubjectCommonName)
	# list of text documents
	text = ["abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"]
	# create the transform
	vectorizer_vector_ks_sub_en = CountVectorizer(analyzer='char',lowercase=False)
	# tokenize and build vocab
	vectorizer_vector_ks_sub_en.fit(text)
	# encode document
	vector_ks_sub_en = vectorizer_vector_ks_sub_en.transform(text)
	# summarize encoded vector
	for en in vector_ks_sub_en.toarray():
		for cn in vector_ks_sub_cn.toarray():
			Ks_stats_Subject_English.append(ks_2samp(cn,en).statistic)
	return Ks_stats_Subject_English

#Kolmogorov-Smirnov statistics for issuer in issuers	
def KolmogorovIssuerandIssuers():
	Ks_stats_Issuer_Issuers=[]
	vectorizer = TfidfVectorizer()
	features=vectorizer.fit_transform(IssuerCommonName).todense()
	for f in features :
		Ks_stats_Issuer_Issuers.append(kstest(f,'norm').statistic)
	return Ks_stats_Issuer_Issuers
	
#Kolmogorov-Smirnov statistic for issuer in English characters
def KolmogorovIssuerEnglish():
	Ks_stats_Issuer_English=[]
	SubjectCommonName,IssuerCommonName=commonName()
	vectorizer_vector_ks_iss_cn = CountVectorizer(analyzer='char',lowercase=False)
	vectorizer_vector_ks_iss_cn.fit(IssuerCommonName)
    vector_ks_iss_cn = vectorizer_vector_ks_iss_cn.transform(IssuerCommonName)
	text = ["abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"]
	vectorizer_vector_ks_sub_en = CountVectorizer(analyzer='char',lowercase=False)
	vectorizer_vector_ks_sub_en.fit(text)
    vector_ks_sub_en = vectorizer_vector_ks_sub_en.transform(text)
	for en in vector_ks_sub_en.toarray():
		for cn in vector_ks_iss_cn.toarray():
			Ks_stats_Issuer_English.append(ks_2samp(cn,en).statistic)
	return Ks_stats_Issuer_English
	
#Kullback-Leiber Divergence for subject in subjects
def KullbackSubjectandSubjects():
    Kl_dist_Subject_Subjects=[]
	SubjectCommonName,IssuerCommonName=commonName()
	vectorizer = CountVectorizer()
	vectors = vectorizer.fit_transform(SubjectCommonName).toarray()
	feature=np.array(vectors[0])
	for f in vectors :
		Kl_dist_Subject_Subjects.append(mutual_info_score(np.array(vectors[0]),np.array(f)))
	return Kl_dist_Subject_Subjects
	
#Kullback-Leiber Divergence for subject in English characters
def KullbackSubjectEnglish():
	Kl_dist_Subject_English=[]
    SubjectCommonName,IssuerCommonName=commonName()
	vectorizer = CountVectorizer(analyzer='char',lowercase=False)
	text = ["abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"]
	vectors = vectorizer.fit_transform(SubjectCommonName).toarray()
	vectors_en= vectorizer.transform(text).toarray()
	for en in vectors_en:
		for cn in vectors:
			Kl_dist_Subject_English.append(mutual_info_score(np.array(cn),np.array(en))) 
	return Kl_dist_Subject_English
	
#Kullback-Leiber Divergence for Issuer in Issuers
def KullbackIssuerandIssuers():
	Kl_dist_Issuer_Issuers=[]
	SubjectCommonName,IssuerCommonName=commonName()
	vectorizer = CountVectorizer()
    vectors = vectorizer.fit_transform(IssuerCommonName).toarray()
    feature=np.array(vectors[0])
	for f in vectors :
		Kl_dist_Issuer_Issuers.append(mutual_info_score(np.array(vectors[0]),np.array(f)))
	return Kl_dist_Issuer_Issuers 
	
#Kullback-Leiber Divergence for issuer in English characters
def KullbackIssuerEnglish():
	Kl_dist_Issuer_English=[]
    SubjectCommonName,IssuerCommonName=commonName()
	vectorizer = CountVectorizer(analyzer='char',lowercase=False)
	text = ["abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"]
	vectors = vectorizer.fit_transform(IssuerCommonName).toarray()
	vectors_en= vectorizer.transform(text).toarray()
	for en in vectors_en:
		for cn in vectors:
			Kl_dist_Issuer_English.append(mutual_info_score(np.array(cn),np.array(en)))
	return Kl_dist_Issuer_English
	
def wildCardValidated():
    x509 = readCert()
	Is_WildCard_Validated=[]
	wild=False
	for cert in x509:
		j= "*."
		if j in cert.get_subject().CN:
				wild=True
		else:
				 wild=False
		Is_WildCard_Validated.append(wild)
	return Is_WildCard_Validated
	
def domainMatchCN():
	Is_domainMatchCN=[]
	x509 = readCert()
	MatchCN=False
	for host in dataset['url']:
		if host in SubjectCommonName:
			MatchCN=True
		else:
			MatchCN=False
		Is_domainMatchCN.append(MatchCN)    
	return Is_domainMatchCN
	
def writeDataset():
    SubjectCommonNameIp=subjectCommonNameIP()
	Is_extended_validated=typeOfCertificate_validated()
	Is_organization_validated=typeOfCertificate_validated()
	Is_domian_validated=typeOfCertificate_validated()
	SubjectHasOrganization=subjectHasOrganization
	IssuerHasOrganization=issuerHasOrganization()
	SubjectHasCompany=subjectHasOrganization
	IssuerHasCompany=issuerHasCompany()
	SubjectHasState=subjectHasState()
	IssuerHasState=issuerHasState()
	SubjectHasLocation=subjectHasLocation()
	IssuerHasLocation=issuerHasLocation()
	Subject_onlyCN=subjectOnlyCN()
	Subject_is_com=subjectiscom()
	Issuer_is_com=issueriscom()
	HasSubjectCommonName,HasIssuerCommonName=subissCommonName()
	Subject_eq_Issuer=subjecteqIssuer()
	SubjectElements,IssuerElements,SubjectLength,IssuerLength,ExtensionNumber=subIssLength()
	Selfsigned=selfSigned()
	Is_free=isFree()
	DaysValidity=daysValidity()
	Domain_ranking=domainRanking()
	Entropy=entropyCommonName()
	Euclidian_Subject_Subjects=euclidianSubjectandSubjects()
	Euclidian_Subject_English=euclidianSubjectEnglish()
	Euclidian_Issuer_Issuers=euclidianIssuerandIssuers()
	Euclidian_Issuer_English=euclidianIssuerEnglish()
	Ks_stats_Subject_Subjects=KolmogorovSubjectandSubjects()
	Ks_stats_Subject_English=KolmogorovSubjectEnglish()
	Ks_stats_Issuer_Issuers=KolmogorovIssuerandIssuers()
	Ks_stats_Issuer_English=KolmogorovIssuerEnglish()
	Kl_dist_Subject_Subjects=KullbackSubjectandSubjects()
	Kl_dist_Subject_English=KullbackSubjectEnglish()
	Kl_dist_Issuer_Issuers=KullbackIssuerandIssuers()
	Kl_dist_Issuer_English=KullbackIssuerEnglish()
	Is_WildCard_Validated=wildCardValidated()
	Is_domainMatchCN=domainMatchCN()
	#zipped all the arrays into one and write in CSV file
	zipbObj = zip(SubjectCommonNameIp,
	Is_extended_validated,
	Is_organization_validated,
	Is_domian_validated,
	SubjectHasOrganization,
	IssuerHasOrganization,
	SubjectHasCompany,
	IssuerHasCompany,
	SubjectHasState,
	IssuerHasState,
	SubjectHasLocation,
	IssuerHasLocation,
	Subject_onlyCN,
	Subject_is_com,
	Issuer_is_com,
	HasSubjectCommonName,
	HasIssuerCommonName,
	Subject_eq_Issuer,
	SubjectElements,
	IssuerElements,
	SubjectLength,
	IssuerLength,
	ExtensionNumber,
	Selfsigned,
	Is_free,
	DaysValidity,
	Domain_ranking,
	Entropy,
	Euclidian_Subject_Subjects,Euclidian_Subject_English,Euclidian_Issuer_Issuers,Euclidian_Issuer_English,
	Ks_stats_Subject_Subjects,Ks_stats_Subject_English,Ks_stats_Issuer_Issuers,Ks_stats_Issuer_English,
	Kl_dist_Subject_Subjects,Kl_dist_Subject_English,Kl_dist_Issuer_Issuers,Kl_dist_Issuer_English,
	Is_WildCard_Validated,Is_domainMatchCN)
	try:
		with open(r'C:\Users\aloka\Desktop\Thesis\4\Dataset\DatasetNew_copy_130cert.csv', 'w') as output:
		writer = csv.writer(output, lineterminator='\n')
		writer.writerows(zipbObj)
	except OSError:
		print "Could not open and write file:"
		sys.exit()
    finally:
        print "exit"
