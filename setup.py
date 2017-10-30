from setuptools import setup
from sys import version


requirements = [
    'click',
]
if int(version[0]) == 3:
    requirements.append('scapy-python3')
    requirements.append('pyx')  # For showing PDF packets
else:
    requirements.append('scapy')
    requirements.append('pyx==0.12.1')  # For showing PDF packets

setup(
    name="scapy_examples",
    version="0.4.0",
    install_requires=requirements,
)
