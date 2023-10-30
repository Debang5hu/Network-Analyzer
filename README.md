# Network-Analyzer
A network analyzer made to detect DOS  

# Getting Started: 

A network analyzer made using *python 3.11* and *scapy*.It captures the network packet and detect for DOS by counting the number of packets send to  
target also logs the information of a captured packet to a pcap file,which can be used later,  
'map.py' can be used to plot the location of ip (publicly available) on map and see the route of the packet.  
'map.py' to be updated later  

-------------------------------------------------------------------------------
# How to use:  

![usage](https://github.com/Debang5hu/Network-Analyzer/assets/114200360/8d43ca3d-8b89-4cda-bb2f-b0e4d74f44c8)  
  

to capture the network packets:  

```
sudo python3 main.py wlan0
```  

![capture](https://github.com/Debang5hu/Network-Analyzer/assets/114200360/739ce9ba-285c-45f4-946e-9a6077569873)  


to see the route of network packet  

```
python3 map.py  
```

![iplocation](https://github.com/Debang5hu/Network-Analyzer/assets/114200360/c7e8e5a9-9d4c-4f0f-b2cc-805c662ab46c)  



-----------------------------------------------------------------------------------  
# Next update:  

to implement ML for DOS detection  

-----------------------------------------------------------------------------------
# Installation:  

## Linux:  

to clone the repository  

```
git clone https://github.com/Debang5hu/Network-Analyzer.git
```  

get into the directory
```
cd Network-Analyzer 
```  

to install the dependencies  

```
pip install -r requirements.txt 
```  

to run the script  

```
sudo python3 main.py wlan0
```



-----------------------------------------------------------------------------------
# Demo:  

https://github.com/Debang5hu/Network-Analyzer/assets/114200360/fec1074c-8b2b-4ec5-8941-0085909a48cd  











