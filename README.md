# Scandy

Scandy is a network vulnerability scanner built with Python.
This works best on Linux (Kali) but to use it on Windows check the branch [old_version](https://github.com/andyboat75/scandy/tree/old_version "old_version")
I have a tutorial of how I developed this scanner on [YouTube](https://youtube.com/playlist?list=PLE9wWR6sJKjEyCgneyZPK_2qk9rggPv1J)
  
## Features  
  
- Scan network for connected(active) devices.
- Retrieve information such as Mac address, OS, Hostname,
- Scan for open ports, port services, port banners and additional vulnerabilities.
- Search for existing CVE for open ports using [Vulners API](https://vulners.com)  

## Installation

Create a Python environment.

```sh
python  -m venv venv
```

Activate the environment

```sh
source ./venv/bin/activate
```

Install the required packages to use

```sh
pip3 install -r requirements.txt
```

### Caution

Because Scapy interacts directly with the raw socket of your system it requires sudo privileges. You can directly call sudo as I have shown below or follow the explanation [here](http://https://github.com/Forescout/project-memoria-detector/issues/6) to tweak it as you want it.

## Usage

|   Commands        |     Description                |
|:-----------------:|:------------------------------:|
| -t or --target    |    Target network ip           |
|  -p or --port     |    port(s) to scan             |
| -th or --thread   | Number of thread. Default 50   |
| -v or --verbose   |  Print all closed ports        |

The command below will check if the IP can be reached and then scan default ports 1-1024

```sh
sudo python scandy.py -t 192.168.227.3
```

The command below will check if the IP can be reached and then scan default port 22, 80, 221

```sh
sudo python scandy.py -t 192.168.227.3 -p 80 22 221
```

The command below will check for all the devices on the network 192.168.227.1/28 that can be reached and then scan default ports 22, 80, 221 and ports in the range of 2000 - 5000

```sh
sudo python scandy.py -t 192.168.227.1/28 -p 80 22 221 -pr 2000 5000
```

**Note:** If you are getting moduleNotFoundError, directly reference Python in the virtual environment as shown below.

```sh
sudo ./venv/bin/python3 scandy.py -t 192.168.227.1/28
```
