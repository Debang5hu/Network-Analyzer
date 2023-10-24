# Network-Analyzer
A network analyzer made to detect DOS  

# Getting Started: 

A network analyzer made using *python 3.11* ,*pcap*,etc.It captures the network packet and logs the information to a txt file,which is used later  
for analyzing dos attack, 'map.py' can be used to plot the location of ip (publicly available) on map and see the route of the packet.  

To be made more efficient in the next update.

-------------------------------------------------------------------------------
# How to use:  

![help](https://github.com/Debang5hu/Network-Analyzer/assets/114200360/24c8b5c1-b114-4a5d-a1da-24e3c408341f)  

to list all the networking interfaces:  

```
./main.py --interfaces all
```  

![interface](https://github.com/Debang5hu/Network-Analyzer/assets/114200360/bf7bc891-8b85-48c3-bcee-5180c5c5c8b6)  

to capture the network packets:  

```
./main.py --capture any
```  

![capture](https://github.com/Debang5hu/Network-Analyzer/assets/114200360/b31cbb02-3913-4fbb-a6cd-fb7ca07179ea)  

to see the route of network packet  

```
python3 map.py  
```

![iplocation](https://github.com/Debang5hu/Network-Analyzer/assets/114200360/c7e8e5a9-9d4c-4f0f-b2cc-805c662ab46c)  

to analyze the captured packet  

```
python3 basicdoschecker.py
```

![example](https://github.com/Debang5hu/Network-Analyzer/assets/114200360/6b7af233-aca6-4bc6-82f2-1c1075243e75)

-----------------------------------------------------------------------------------  
# Next update:  

to make it better  
to implement ML for DOS detection

-----------------------------------------------------------------------------------
# Installation:  

## Linux:  

```
git clone https://github.com/Debang5hu/Network-Analyzer.git
```  

```
cd Network-Analyzer 
```  

```
chmod +x setup.sh 
```  

```
./setup.sh 
```  

-----------------------------------------------------------------------------------
# Demo:  

https://github.com/Debang5hu/Network-Analyzer/assets/114200360/9170048b-0ba4-4e87-9a54-dcd7d7973216








