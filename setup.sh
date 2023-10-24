#!/bin/bash

#updating and upgrading
sudo apt update && apt upgrade -y

#clear the screen
clear

#installing requirements.txt
pip install -r requirements.txt && clear


#give permission to the file
sudo chmod +x main.py

#create a file where the ip will be stored(optional)
touch ip.txt && clear

#to run the script
./main.py -h

#to mark the rough location of the ip on map and opening it on browser:
#python3 map.py

#to see the number of packets transmitted between ip's:
#python3 basicdoschecker.py
