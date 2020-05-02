# ML-DomainPhishingDetection

                                                **Web API and Proof-of-Concept Web Application**
                                    
Web API provides application interface to user over the internet. 
It handles user request and returns output through web service. 
As there are many popular web frameworks that supports an environment to develop a Web API. 
In my reseach, Flask framework was used to create Web API for auto-detection of a phishing domain. 
The flask is easy to install and contained several tools, libraries, and technologies to build a web application. 
This web application allows a user to identify whether a domain visited is legitimate or phishing on frontend.
As the backend classification part of the Web API, the decision tree machine learning classifier is implemented using the Python programming language.
HTML and CSS are used for creating page structure and styling of web page. 
In addition, JavaScript provides dynamic functionality to web page by handling HTML elements. 
Based on the output of backend functions(feature creation, decision rules and certificate extraction), JavaScript action method call on check box to response the user input request and show the result on screen.
Main functionalities of Web API are:
* It must identify phishing and legitimate domain based on decision tree classification rules.
* It must return an error message on wrong input data.
* It must successfully create features using different Python library method.
* It must extract the certificate from the website without any error because phishing domains are active for very short span of time.
* It would not detect any types of web attack such as Distributed Denial of Service (DDOS) etc.
* Input data should be a website domain name.

The flow chart of this framework is below




![Flow_chartAPI_new](https://user-images.githubusercontent.com/55644004/80871739-5c47c300-8c84-11ea-84ad-a797dfc46cbb.jpg)
                               
                               
                               
                               
                               
                               
                               
                               
                               
                               
                               
                               
                               
                               
                               
                               
                               
                               
                               
                               
                               
                               
                               
                               
                               
                               
                               
                               
                               
                               Fig 1.1
                               
The flow chart of the framework is explained below:

* Input is domain of the a website.
* Extraction of certificate from the input domain. 
* Features are created for a certificate.
* Decision Tree classifier rules are employed to classify category of the domain.
* The result shows that a domain was legitimate or phishing domain.
                                                            
                                                       
                                                             **Working**

Python version- 3.5
Flask version- 1.1.1
Operating system- Windows 10

Before installing flask, python has to install in the system.
The frontant and backend are connected using flask. The frontend code is saved in api.html and backend code is saved in api.py. The static folder contains
javascript, image and style files that are used for styling the web page of application.
The api.html should be saved in templates folder and static files in static folder that are the requirements of flask in order to work.
Below screenshots show the running server through web service:

![example of legitimate domain](https://user-images.githubusercontent.com/55644004/80871724-45a16c00-8c84-11ea-93d3-fda8c3035b73.png)
![example of phishing domain](https://user-images.githubusercontent.com/55644004/80871717-3fab8b00-8c84-11ea-9a72-4770e3667fe8.png)


The web application also returns an error message on wrong input data. 
It shows error messages on screen when input request is empty or input data is other than domain name of the website.
Below are examples of error messages.
![example of error case 1_copy](https://user-images.githubusercontent.com/55644004/80871721-42a67b80-8c84-11ea-9915-34336685bf74.png)
![example of error case 2](https://user-images.githubusercontent.com/55644004/80871723-43d7a880-8c84-11ea-992a-42e400733056.png)


References
1. Ssl - TLS/SSL wrapper for socket objects. (n.d.). Retrieved April 29, 2020, from https://docs.python.org/3/library/ssl.html
2. Python One-liner to get your site's Alexa Rank. Retrieved April 29, 2020, from https://gist.github.com/masnun/3170870
3. Cryptographic library.  http://openssl.cs.utah.edu/docs/crypto/crypto.html.
4. Publicsuffix2.  https://pypi.org/project/publicsuffix2/.
5. Explainwhatflaskisanditsbenefits?,Oct2019.https://www.i2tutorials.com/technology/explainwhatflaskisanditsbenefits/















