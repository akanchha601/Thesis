# Overview
Due to the phishing sites appearing genuine to users, detecting them is a challenging
task. The SSL certificate that is generally used to secure and encrypt the communication, can also be generated for the phishing sites. The consequences of using the
HTTPS phishing sites could be harmful to users. Attackers can easily trap users and
steal sensitive information using the cloned website that looks legitimate along with
its SSL certificate. This may also result in the degradation of the user’s trust and
belief in “green padlock” and “lock icon” shown on the browser after connecting to
a web site through HTTPS. In this thesis, I have studied the important attributes
of how attackers use SSL certificates in sites with fake domains. As a result, I have
explored the robustness of a system to auto-detect a phishing site using the critical
attributes of an SSL certificate. The proposed system uses different Machine Learning
algorithms that utilize extracted SSL certificate features studied. Considering good
performance and transparency in the resulting model, I have chosen the decision tree
algorithm for decision making of site category. The algorithm defines a set of decision
rules to classify whether the site is a legitimate site or a phishing site. The proposed
classifier has achieved around 97% of correctly classified instances in comparison with
other machine learning classifiers. In order to connect users to the system, a Web API
is created which provides the user interface of the proposed system through HTTP
service. The API verifies single domain as legitimate or phishing domain by using
the decision rules of decision tree algorithm. Evaluation results show the promising
effectiveness and efficiency of the Web API system designed and developed.

# Description

In this research, a robust machine learning classifier with different features was explored to identify legitimate and phishing domains. The identification was based on
the features of SSL certificates generated for registered domains. By use of Python
scripts, the connections were made with more than 100 domains on TCP port 443 and
their SSL certificates were retrieved along with creating 42 features-boolean, integer
and text features. Two scripts (certificate extraction and feature creation) were used
for collecting training and testing datasets. The different characteristics of domains
and certificates for both legitimate and phishing classes were analyzed with collected
data samples. The final dataset was formed with J48 decision tree after observing
the behaviour and performance of the decision tree. It was analyzed that the performance of the trained model increased as the number of data samples increased with
different characteristics. In addition, by using feature selection methods, the training
speed and performance of the models were improved after removing the unnecessary
features. Out of 42, only 31 features were considered to prepare the final training
dataset. After selecting the suitable machine learning classifier based on the performance results of the ten-fold cross validation, the performance of the selected model
was examined with different sets of features. One set consists of text-features and the
other consists of without text features. The robustness of these decision tree classification models were analyzed by four sets of test cases where similar and dissimilar
characteristics of (compared to the training) of data were included. The results of
each case provided the performance difference of With text features and Without text
features. The obtained results for Without text features decision model performed
well in almost every case for both classes as compared to With text features. Thus,
Without text features decision model was proposed to classify legitimate and phishing
domains.The architecture of the proposed system is provided below:


![Architecture3](https://user-images.githubusercontent.com/55644004/84404986-85d60180-abd5-11ea-9ee3-2ddfd7785a27.png)



As per my knowledge, this is first effort towards analyzing the classifier robustness of the trained models with different features. With these evaluations, it was
easy to estimate the effectiveness and consistency of the classifiers if the attackers
changed their patterns in phishing. With decision tree classifier, the hidden patterns
and indicators were recognized in the SSL certificate. The decision tree classifier
made it easier for me to interpret the decision rules because of its human readable
rules and visualization property. By comparing and analyzing the differences in each
test case performances of both decision trees, the robust classifier was explored with
respective features. As the dataset had only 160 data samples (80 legitimate and 80
phishing domains), these results could be taken as preliminary but promising results
in detecting the phishing domains.
# Key Findings
Finally, on the basis of analyzed domains and certificates patterns between legitimate
and phishing classes, I observe the following:
1. Attackers use free certificates issued by CA such as “Let’s Encrypt Authority
X3”, “cPanel, Inc. Certification Authority”. However, these free web certificates are available mainly for start-up companies who can not afford expensive
SSL certificate but attackers use these methods for phishing purposes.
2. Attackers use domain validated and wild card certificates. They do not seem to
purchase organization or extended validated certificates as it may disclose their
actual purposes and personal details. CA strictly verifies provided information
before issuing organization or extended validated certificates.
3. Attackers seem to use SSL certificates that are valid for only 90 days. These
provide enough time to fool internet users by showing encrypted traffic.
4. Attackers tend to use the fake domains with self-signed certificates where they
issue the SSL certificate to themselves by employing free SSL certificate tools.
