Goal: Provide some examples of the scapy framework to allow those with some knowledge of python to get started playing with and exploring lower level networking, e.g. by modifying those examples to (in)validate assumptions.

Getting started:
  - pip install .
  - 'show' examples should work without root:
    - show/example_ping.py  # This will show various dissections of an example packet including how to reproduce it with scapy.
  - 'sniff' examples will require running as root:
    - sniff/show_http_hosts_visited.py  # Now visit a website in your browser and observe the sites being listed.
  - 'do' examples will require running as root:
    - do/arp.py -i <interface, see --help for options> -d <destination IP- e.g. try your default gateway>
    - do/dns.py -q <query type, e.g. A> -H <host name to query, e.g. github.com> -r <your favourite resolver's IP address, e.g. one from https://dns.watch>

OSX:
  Prerequisites:
    - brew install libdnet
    - brew cask install mactex  # Only for displaying pdfs (untested)

Ubuntu (and debian?):
  Prerequisites:
    - apt-get install python-pyx  # Only for displaying pdfs

Windows:
  Prerequisites:
    - Ensure windows prereqs for scapy are installed: http://scapy.readthedocs.io/en/latest/installation.html#windows
