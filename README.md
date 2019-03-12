![Honeygrove](https://github.com/UHH-ISS/honeygrove/raw/master/wiki_resources/honeygrove_logo.png)

Honeygrove is a modular honeypot based on Python that builds upon [Broker](https://github.com/zeek/broker) and the [Twisted Framework](https://twistedmatrix.com/trac/wiki).

### System Requirements

Honeygrove was tested on Ubuntu 16.4 and Debian 9.1. It may work on other distributions. If Broker is not available, the honeypot itself can be used without it. Currently there is no possibility to communicate with the management-console or the monitoring stack without Broker.


### Quickstart Guide

* Clone the repository or download and unzip it
* Optional: Setup a virtualenv to contain the required dependencies
  ```shell
  $ python3 -m venv .venv
  $ source .venv/bin/activate
  ```
* Install the required python dependencies
  ```shell
  $ pip3 install --upgrade -r requirements.txt
  ```
* Optional: Install [`broker`](https://github.com/zeek/broker) and the python bindings to communicate with a CIM
* Create the honeygrove main directory and some required subdirectories
  ```shell
  $ mkdir -p /var/honeygrove/{logs,resources/{quarantine,honeytoken_files}}
  ```
* Copy the provided example resources to the main directory
  ```shell
  $ cp -a resources /var/honeygrove
  ```
* Edit the configuration file to fit your needs
  ```shell
  $ $EDITOR honeygrove/config.py
  ```
* Start honeygrove and verify everything works as expected
  ```shell
  $ sudo python3 -m honeygrove
  ```

For further information see our [wiki](https://github.com/UHH-ISS/honeygrove/wiki) (currently only the user guide for honeygrove is available in english).


### Contributors

Honeygrove was initially developed as a bachelor project of the [IT-Security and Security Management](https://www.inf.uni-hamburg.de/inst/ab/snp/home.html) working group at Universität Hamburg and subsequently improved.

Contributors that agreed to be named are:

* [Arne Büngener](https://github.com/4rne)
* Alexandra Lindt
* [Adrian Miska](https://github.com/AdrianMiska)
* [Frieder Uhlig](https://github.com/Moshtart)
* [Julian 4goettma](https://github.com/4goettma)
