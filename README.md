![Honeygrove](https://github.com/UHH-ISS/honeygrove/raw/master/wiki_resources/honeygrove_logo.png)

Honeygrove is a modular honeypot based on Python and building upon [Broker](http://bro.github.io/broker/) and the [Twisted Framework](https://twistedmatrix.com/trac/wiki).

### System requirements

Honeygrove was tested on Ubuntu 16.4 and Debian 9.1. It may work on other distributions. If Broker is not available, the honeypot itself can be used without it. Currently there is no possibility to communicate with the management-console or the monitoring stack without Broker.


### Install guide

* clone the repository or download and unzip it
* copy the `/honeygrove` directory where you want to install it
* run `honeygrove_install` with root privileges to install the dependencies
* choose if you want to install broker
* remember to look at config.py before you start the honeypot for the first time

For further information see our [wiki](https://github.com/UHH-ISS/honeygrove/wiki) (currently only the user guide for honeygrove is available in english).


### History

Honeygrove was initially developed as a bachelor project of the [IT-Security and Security Management](https://www.inf.uni-hamburg.de/inst/ab/snp/home.html) working group at Universität Hamburg.<br/>
Members of the project that agreed to be named are:

* [Arne Büngener](https://github.com/4rne)
* Alexandra Lindt
* [Adrian Miska](https://github.com/AdrianMiska)
* [Frieder Uhlig](https://github.com/Moshtart)
