from setuptools import setup
from sys import version


requirements = [
    'netifaces',
    'scapy',
]
if int(version[0]) == 3:
    requirements.append('pyx')  # For showing PDF packets
else:
    requirements.append('pyx==0.12.1')  # For showing PDF packets

setup(
    name="scapy_examples",
    version="0.4.3",
    install_requires=requirements,
)
