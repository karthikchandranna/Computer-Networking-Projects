#!/usr/bin/env python

import socket
import select
import re
import sys
from bs4 import BeautifulSoup

# accepting username and password from the user as command line arguments
username = sys.argv[1]
password = sys.argv[2]

# creating socket
sockfd = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

# defining the server name and the port number
serverName = "cs5700f14.ccs.neu.edu"
loginHostname = "http://cs5700f14.ccs.neu.edu/accounts/login/?next=/fakebook/"
port = 80

# preparing the initial GET request line
requestMsg = "GET "+loginHostname+" HTTP/1.1\nHost: "+serverName+"\n\n"

# connecting the server to the specified port of the client machine using a scoket
sockfd.connect((serverName,port))

# sending encoded HTTP request message to the server
sockfd.send(requestMsg.encode())

# receiving HTTP response message from the server
resultGet = sockfd.recv(4096)

# retrieving the session id from the response message
sessionString = 'sessionid'
indexOfSessionString = resultGet.find(sessionString)
indexOfSessionString = indexOfSessionString + 1 + len(sessionString)
substring = resultGet[indexOfSessionString:]
session = substring.split(';',1)
sessionid = session[0]

# retrieving the csrf token from the response message
soup = BeautifulSoup(resultGet)
csrfName = soup.find(attrs={"name" : "csrfmiddlewaretoken"})
csrfValue = csrfName['value']

# preparing the header of the POST request message
requestPost = ("POST http://cs5700f14.ccs.neu.edu/accounts/login/ HTTP/1.1\n"+
               "Accept:text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\n"+
               "Accept-Encoding:gzip,deflate\n"+
               "Accept-Language:en-GB,en-US;q=0.8,en;q=0.6\n"+
               "Cache-Control:max-age=0\n"+
               "Content-Length:109\n"+
               "Content-Type:application/x-www-form-urlencoded\n"+
               "Cookie: csrftoken="+csrfValue+"; sessionid="+sessionid+"\n"+
               "Host:cs5700f14.ccs.neu.edu\n"+
               "Origin:http://cs5700f14.ccs.neu.edu\n"+
               "Proxy-Connection:keep-alive\n"+
               "Referer:http://cs5700f14.ccs.neu.edu/accounts/login/?next=/fakebook/\n"+
               "User-Agent:Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.124 Safari/537.36\n\n"+
               "username="+username+"&password="+password+"&csrfmiddlewaretoken="+csrfValue+"&next=%2Ffakebook%2F")

# sending encoded HTTP POST request message
sockfd.send(requestPost.encode())

#receiving HTTP response message
resultPost = sockfd.recv(4096)

# retrieving the session id from the response message
sessionString = 'sessionid'
indexOfSessionString = resultPost.find(sessionString)
indexOfSessionString = indexOfSessionString + 1 + len(sessionString)
substring = resultPost[indexOfSessionString:]
session = substring.split(';',1)
sessionid = session[0]

# storing the repsonse message of the POST request in temporary variables
resultMsgWhile = resultPost
requestMsgwhile = requestPost

# initializing lists with the fakebook homepage as the first page to crawl
urlList = ['http://cs5700f14.ccs.neu.edu/fakebook/']
finalUrls = ['http://cs5700f14.ccs.neu.edu/fakebook/']
location = 'http://cs5700f14.ccs.neu.edu/fakebook/'

# loop to traverse all pages of the fakebook website and fetch all the URLs
while(len(urlList) > 0):

        # extracting the status code
        slicedMsg = resultMsgWhile
        statusCode = slicedMsg[9:12]

        # preparing the header of a HTTP GET request message
        requestWhile = ("Accept:text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\n"+
                        "Accept-Language:en-US,en;q=0.8,ms;q=0.6\n"+
                        "Cache-Control:max-age=0\n"+
                        "Connection:keep-alive\n"+
                        "Cookie: csrftoken="+csrfValue+"; sessionid="+sessionid+"\n"
                        "Host:"+serverName+"\n"
                        "User-Agent:Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.124 Safari/537.36\n\n")
        
        # when the status code is 301/302 -> Moved Permanently/ Temporarily
        if (statusCode == '302' or statusCode == '301'):
                # extracting the address of the new location
                locationString = 'Location:'
                indexOfLocationString = resultMsgWhile.find(locationString)
                indexOfLocationString = indexOfLocationString + 1 + len(locationString)
                subLocationstring = resultMsgWhile[indexOfLocationString:]
                locationField = subLocationstring.split('\n',1)
                location = locationField[0]

                # sending a GET request and receiving a response
                requestMsgWhile = "GET "+ location+" HTTP/1.1\n"+requestWhile
                sockfd.send(requestMsgWhile.encode())
                resultMsgWhile = sockfd.recv(4096)

        # when the status code is 500/501/502 -> Internal Server Error
        elif (statusCode == '500' or statusCode == '501' or statusCode == '502'):
                # resending the previous GET request and receiving a response
                requestMsgWhile = "GET "+location+" HTTP/1.1\n"+requestWhile
                sockfd.send(requestMsgWhile.encode())
                resultMsgWhile = sockfd.recv(4096)

        # when the status code is 200 -> message exchange has been successfull
        elif (statusCode == '200'):
                # check if the entire message is received
                while (resultMsgWhile.find('</html>') < 0):
                        resultMsgWhile = resultMsgWhile+sockfd.recv(4096)
                #create a soup out of the response received
                soup = BeautifulSoup(resultMsgWhile)
                # find all the URLs in the page
                for url in soup.findAll('a'):
                        completeUrl= "http://"+serverName+url.get('href')
                        # checking if both the lists do not already have this URL and that the link is a fakebook link and not other websites' link
                        if ((completeUrl.find('fakebook')>0) and (not(completeUrl in finalUrls)) and (not(completeUrl in urlList))):
                                # adding the url to the lists
                                urlList.append(completeUrl)
                                finalUrls.append(completeUrl)

                # pop the current URL from the list
                location = urlList.pop(0);
                # sending a GET request and receiving a response
                requestMsgWhile = "GET "+location+" HTTP/1.1\n"+requestWhile
                sockfd.send(requestMsgWhile.encode())
                resultMsgWhile = sockfd.recv(4096)

        # when the status code is 400/403/404 -> client error or page not found
        elif (statusCode == '400' or statusCode == '403' or statusCode == '404'):
                # pop and abandon the current URL from the list
                urlList.pop(0)
                finalUrls.pop(0)

        # when the status is blank. A case of chunked-encoding or server closing connection
        elif (statusCode == ''):
                # recreating the socket
                sockfd.close()
                sockfd = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                sockfd.connect((serverName,port))
                # sending a GET request and receiving a response
                requestMsgWhile = "GET "+location+" HTTP/1.1\n"+requestWhile
                sockfd.send(requestMsgWhile.encode())
                resultMsgWhile = sockfd.recv(4096)
        else:
                urlList.pop(0)

# obtaining the disticnt URLs
distinctUrls = list(set(finalUrls))

popNextUrl = 1
secretFlagCount = 0

# loop to traverse all the URLs in the fakebook website and retreive the security flag
while (len(distinctUrls) > 0):
        if (popNextUrl == 1):
                currentUrl = distinctUrls.pop(0)

                # preparing the HTTP GET request header
                requestHeader = ("Accept:text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\n"+
                                 "Accept-Language:en-US,en;q=0.8,ms;q=0.6\n"+
                                 "Cache-Control:max-age=0\n"+
                                 "Connection:keep-alive\n"+
                                 "Cookie: csrftoken="+csrfValue+"; sessionid="+sessionid+"\n"
                                 "Host:"+serverName+"\n"
                                 "User-Agent:Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.124 Safari/537.36\n\n")

                # preparing the GET request message
                requestParse = "GET "+currentUrl+" HTTP/1.1\n"+requestHeader
                # sending a GET request and receiving a response
                sockfd.send(requestParse.encode())
                resultParse = sockfd.recv(4096)

        # obtaining the status code
        slicedMsg = resultParse
        statusCode = slicedMsg[9:12]

        # when the status code is 301/302 -> Moved Permanently/ Temporarily
        if (statusCode == '302' or statusCode == '301'):
                # extracting the address of the new location
                locationStringParse = 'Location:'
                locationParse = resultParse.find(locationStringParse)
                locationParse = locationParse + 1 + len(locationStringParse)
                subLocationstringParse = resultParse[locationParse:]
                locationFieldParse = subLocationstringParse.split('\n',1)
                currentUrl = locationFieldParse[0]
                # sending a GET request and receiving a response
                requestParse = "GET "+ currentUrl+" HTTP/1.1\n"+requestHeader
                sockfd.send(requestParse.encode())
                resultParse = sockfd.recv(4096)
                popNextUrl = 0

        # when the status code is 500/501/502 -> Internal Server Error
        elif (statusCode == '500' or statusCode == '501' or statusCode == '502'):
                # resending the previous GET request and receiving a response
                requestParse = "GET "+currentUrl+" HTTP/1.1\n"+requestHeader
                sockfd.send(requestParse.encode())
                resultParse = sockfd.recv(4096)
                popNextUrl = 0

        # when the status code is 200 -> message exchange has been successfull
        elif (statusCode == '200'):
                # check if the entire message is received. If not, receive the remaining message
                while (resultParse.find('</html>') < 0):
                        resultParse = resultParse+sockfd.recv(4096)
                #create a soup out of the response received
                soup = BeautifulSoup(resultParse)
                # find h2 tags with class= secret_flag
                flagList = soup.findAll("h2", {"class": "secret_flag"})

                
                while (len(flagList) > 0):
                        # extracting the value of the h2 tag with class= secret_flag
                        flagSymbol = 'FLAG: '
                        flagString = str(flagList.pop(0))
                        indexOfFlagString = flagString.find(flagSymbol)
                        indexOfFlagString = indexOfFlagString + len(flagSymbol)
                        subFlagString = flagString[indexOfFlagString:]
                        flagStringAlmost = subFlagString.split('<',1)
                        flag = flagStringAlmost[0]
                        if (len(flag) > 0):
                                # print the secret_flag
                                print flag
                                # increment the secret flag counter
                                secretFlagCount = secretFlagCount + 1

                popNextUrl = 1

        # when the status code is 400/403/404 -> client error or page not found
        elif (statusCode == '400' or statusCode == '403' or statusCode == '404'):
                # pop and abandon the current url
                popNextUrl = 1

        # recreating the socket
        elif (statusCode == ''):
                # recreating the socket
                sockfd.close()
                sockfd = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                sockfd.connect((serverName,port))
                # sending a GET request and receiving a response
                requestParse = "GET "+currentUrl+" HTTP/1.1\n"+requestHeader
                sockfd.send(requestParse.encode())
                resultParse = sockfd.recv(4096)

        else:
                popNextUrl = 1

        # break the loop if you have got all the 5 flags
        if (secretFlagCount == 5):
                break

# close socket connection
sockfd.close
