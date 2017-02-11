from setuptools import setup
from sys import version


requirements = [
    'click',
]
if int(version[0]) == 3:
    requirements.append('scapy-python3')
else:
    requirements.append('scapy')

setup(
    name="scapy_examples",
    version="0.1.0",
    install_requires=requirements,
)
